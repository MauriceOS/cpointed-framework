# cpointed

Security research framework for hosting control panels — cPanel/WHM, DirectAdmin, Mailman — and WordPress. Runs CVE-labelled checks, exports structured evidence, and provides gated exploit and persistence primitives for authorized engagements.

**Author:** Sn0w8ird (MauriceOS) · **License:** MIT · **Authorized use only**

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
║  v1.0.0  |  Red Team Framework  |  MIT  |  Authorized Use Only   ║
║  Sn0w8ird / MauriceOS                                            ║
║                                                                  ║
║  14 exploits  8 auxiliary  5 post  12 persistence                ║
╚══════════════════════════════════════════════════════════════════╝
```

## Install

Requires Python 3.10+.

```bash
pip install -e ".[tui]"          # Textual dashboard
pip install -e ".[remediation]"  # paramiko SSH helpers
pip install -e ".[dev]"          # test suite
```

## Usage

```bash
# Fingerprint and scan a host
cpointed scan --host 10.0.0.1 --port 2083 --fingerprint

# Batch scan from a target file, write JSON and HTML reports
cpointed scan --targets-file targets.txt --json-out out.json --html-out out.html

# CIDR sweep
cpointed scan --cidr 10.0.0.0/24

# Include WordPress plugin modules
cpointed scan --host 10.0.0.1 --wordpress

# WordPress discovery and dedicated scan
cpointed wp discover --url https://target.example/
cpointed wp scan --host 10.0.0.1 --port 443

# Run an exploit module (requires CPOINTED_AUTHORIZED=1)
export CPOINTED_AUTHORIZED=1          # PowerShell: $env:CPOINTED_AUTHORIZED = '1'
cpointed exploit --cve CVE-2026-41940 --host 10.0.0.1 --port 2087
cpointed exploit --cve CVE-2026-1357  --host 10.0.0.1 --port 8080 --no-ssl

# Blue-team remediation checklist
cpointed remediate --plan-only

# Interactive TUI
cpointed tui
```

`CPOINTED_AUTHORIZED=1` is required for exploit, persistence, and `local deploy-mu-probe` operations. The banner is suppressed on non-TTY stdout; use `--no-banner` or `CPOINTED_NO_BANNER=1` to suppress it explicitly.

Run `cpointed --help` or `cpointed <command> --help` for the full option reference.

## Modules

**cPanel / WHM**

| Module | Type |
|--------|------|
| `CVE-2024-34015` | scan |
| `CVE-2025-24832` | scan |
| `CVE-2026-41940` | exploit (auth-gated) |
| `SEC-585` | scan |

**DirectAdmin**

| Module | Type |
|--------|------|
| `CVE-2021-46417` | scan |
| `CVE-2025-56551` | scan |

**Mailman**

| Module | Type |
|--------|------|
| `CVE-2025-43921` | scan |

**WordPress** — pass `--wordpress` to `scan` or use `wp scan`

| Module | Plugin / Theme |
|--------|----------------|
| `CVE-2026-1357` | WPvivid Backup & Restore |
| `CVE-2026-2991` | KiviCare |
| `CVE-2025-13374` | Kalrav AI Agent |
| `CVE-2026-5294` | Geeky Bot |
| `CVE-2026-7567` | Temporary Login Without Password |
| `CVE-2026-6261` | Betheme |
| `CVE-2026-3454` | GenerateBlocks |

Pass the module ID to `exploit --cve <ID>` for modules with an exploit path.

## Lab setup

See [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md) for a Docker-based lab with cPanel and WordPress targets.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Legal

For authorized security assessments and blue-team hardening only. Unauthorized access to computer systems is illegal. You are responsible for ensuring all use complies with applicable law and any contractual obligations. The MIT License does not authorize misuse; see `LICENSE` for the full disclaimer.
