# cpointed

**Owner:** Sn0w8ird · **License:** MIT (see `LICENSE` and `AUTHORS`)

## Banner

On interactive CLI and TUI startup, cpointed prints a Metasploit-style frame defined in [`cpointed/core/banner.py`](cpointed/core/banner.py). Module counts and the user line are **dynamic**; the block below is a representative snapshot.

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

Modular Python toolkit for **authorised** security work on hosting stacks: cPanel/WHM, DirectAdmin, related daemons, and WordPress plugin risk modules. It provides a scan engine, pluggable checks, JSON/HTML reporting, a Textual TUI, and gated exploit hooks. A desktop GUI remains a stub.

## Legal (read first)

Use this software only for **authorised** assessments, **blue-team** hardening, and **controlled** research. **Unauthorized access to computer systems is illegal.** Exploit and persistence paths expect **explicit written permission** from the system owner and **`CPOINTED_AUTHORIZED=1`** where the code enforces it. You are responsible for complying with law and contract.

The MIT License does not authorise misuse. See the disclaimer in `LICENSE`.

## Features

- Control-panel oriented modules (e.g. cPanel, DirectAdmin) plus optional WordPress CVE-style modules when you pass `--wordpress` on `scan`.
- Async scanning, fingerprinting, CIDR and target-file inputs, optional port discovery.
- **`exploit`** command with CVE-style module selection (gated; **`--dry-run`** where supported).
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

# Exploit hook (requires authorisation gates in the module; pass CVE id your build expects)
cpointed exploit --cve CVE-2026-41940 --host 127.0.0.1 --port 2083

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
