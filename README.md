# cpointed

**Owner:** Sn0w8ird · **License:** MIT (see `LICENSE` and `AUTHORS`)

```text
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ██████╗██████╗  ██████╗ ██╗███╗   ██╗████████╗███████╗██████╗ ║
║   ██╔════╝██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗║
║   ██║     ██████╔╝██║   ██║██║██╔██╗ ██║   ██║   █████╗  ██║  ██║║
║   ██║     ██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║   ██╔══╝  ██║  ██║║
║   ╚██████╗██║     ╚██████╔╝██║██║ ╚████║   ██║   ███████╗██████╔╝║
║    ╚═════╝╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═════╝ ║
║                                                                  ║
║         Red Team Framework | Hosting Control Panel Security      ║
║                   v1.0.0 | Authorized Use Only                   ║
║                                                                  ║
║                Built by: Sn0w8ird                                ║
║                Licensed to: MauriceOS                            ║
╠══════════════════════════════════════════════════════════════════╣
║  + ---[ 13 exploits - 8 auxiliary - 5 post                       ║
║  + ---[ 12 payloads - 6 encoders - 2 nops                        ║
║  + ---[ Free for authorized use only                             ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ☺  Welcome to cpointed – Red Team for Hosting Control Panels    ║
║                                                                  ║
║  ● Logged in as: operator                                        ║
║    operator@localhost:~/cpointed [main]                          ║
║                                                                  ║
║  ──────────────────────────────────────────────────────────────  ║
║  Enter a command or use --help. For destructive actions, set     ║
║  CPOINTED_AUTHORIZED=1 in your environment.                      ║
║  ──────────────────────────────────────────────────────────────  ║
╚══════════════════════════════════════════════════════════════════╝
```

**cpointed** is meant for **real** red-team and blue-team workflows on hosting stacks: fingerprint services, run **CVE-labelled checks** against panels and WordPress sites, export evidence, triage in the TUI, and invoke **gated** exploit hooks only where you have permission and `CPOINTED_AUTHORIZED=1` when modules require it. A desktop GUI remains a stub.

## How teams use it

- **Panel discovery:** `scan` with `--fingerprint`, optional `--discover-ports`, CIDR or `--targets-file` for batches.
- **WordPress surface:** `wp discover --url …` for path hints, or `wp scan` / `scan --wordpress` to include plugin-oriented modules.
- **Evidence:** `--json-out` and `--html-out` on `scan` (and `wp scan`) for reporting.
- **Controlled validation:** `exploit --cve <exact-module-name>` against lab targets with the right host, port, and SSL flags.
- **Defence follow-up:** `remediate --plan-only` (or execute where appropriate), plus `local` helpers for bundle and enumeration tasks.
- **Ops UI:** `cpointed tui` for an interactive scan dashboard.

## Supported CVE and advisory modules

Use these identifiers with `exploit --cve …` when the module implements an exploit path; use `scan` / `wp scan` for fingerprint and vulnerability checks. Names match the module `name` field (hyphenated CVE form).

**cPanel / WHM**

- **CVE-2024-34015**
- **CVE-2025-24832**
- **CVE-2026-41940** — staged cPanel/WHM research chain (authorisation-gated)
- **SEC-585** — WHM locale / unserialization-style surface (vendor advisory reference; fingerprint-oriented)

**DirectAdmin**

- **CVE-2021-46417**
- **CVE-2025-56551**

**Mailman**

- **CVE-2025-43921**

**WordPress** (included when you pass `--wordpress` on `scan` or run `wp scan`)

- **CVE-2026-1357** — WPvivid Backup & Restore
- **CVE-2026-2991** — KiviCare
- **CVE-2025-13374** — Kalrav AI Agent
- **CVE-2026-5294** — Geeky Bot
- **CVE-2026-7567** — Temporary Login Without Password
- **CVE-2026-6261** — Betheme
- **CVE-2026-3454** — GenerateBlocks

## Legal (read first)

Use this software only for **authorised** assessments, **blue-team** hardening, and **controlled** research. **Unauthorized access to computer systems is illegal.** Exploit and persistence paths expect **explicit written permission** from the system owner and **`CPOINTED_AUTHORIZED=1`** where the code enforces it. You are responsible for complying with law and contract.

The MIT License does not authorise misuse. See the disclaimer in `LICENSE`.

## Features

- Control-panel oriented modules (e.g. cPanel, DirectAdmin) plus optional WordPress CVE-style modules when you pass `--wordpress` on `scan`.
- Async scanning, fingerprinting, CIDR and target-file inputs, optional port discovery.
- **`exploit`** with `--cve` matching a module id from **Supported CVE and advisory modules** (gated; **`--dry-run`** where supported).
- **`wp`** subcommands: `discover` (base URL probes) and `scan` (HTTP module surface against a host).
- **`remediate`** for curated cPanel-oriented checklist output (and optional local execution on Linux/WSL).
- **`local`** utilities (enumeration, operator bundle helpers, stubs) for lab and recovery workflows.
- **Startup banner** (ASCII branding, version, dynamic module counts): shown on interactive CLI runs; use **`--no-banner`** or set **`CPOINTED_NO_BANNER=1`** to suppress it. The TUI shows the same banner in a scrollable strip at the top.

## Requirements

- Python **3.10+**

## Install

```bash
pip install -e ".[tui]"
```

Optional extras:

- **`[tui]`** — Textual + Rich for `cpointed tui`
- **`[remediation]`** — Paramiko-backed helpers
- **`[dev]`** — pytest stack for contributors

## CLI examples

Entry points: `cpointed` (console script) or `python -m cpointed` (same as `python -m cpointed.cli.main`).

```bash
# Scan a single host with service fingerprint
cpointed scan --host 127.0.0.1 --port 2083 --fingerprint

# Include WordPress modules in the engine run
cpointed scan --host 127.0.0.1 --wordpress

# Batch scan with reports
cpointed scan --targets-file targets.txt --json-out report.json --html-out report.html

# Skip the startup banner (non-TTY stdout skips it automatically)
cpointed --no-banner scan --host 127.0.0.1

# Exploit hook — use exact module name (see Supported CVE list)
export CPOINTED_AUTHORIZED=1    # Unix/macOS when the module requires it
# PowerShell: $env:CPOINTED_AUTHORIZED = '1'
cpointed exploit --cve CVE-2026-41940 --host 127.0.0.1 --port 2083
cpointed exploit --cve CVE-2026-1357 --host 127.0.0.1 --port 443 --ssl

# WordPress HTTP discovery / module scan
cpointed wp discover --url https://lab.example/
cpointed wp scan --host 127.0.0.1 --port 8080 --path /

# Blue-team checklist
cpointed remediate --plan-only

# Textual dashboard
cpointed tui
```

Use **`cpointed --help`** and **`cpointed <command> --help`** for the full option set.

## Lab environment

For a defensive, container-oriented workflow (with licensing cautions for any third-party panel images), see **`docs/LAB_SETUP.md`**.

## Contributing

See **`CONTRIBUTING.md`** (MIT contributions, ethics, tests).
