# cpointed

**Owner:** Sn0w8ird · **License:** MauriceOS (see `LICENSE`)

cpointed is a modular Python framework for **authorized** security research around
hosting control panels (cPanel/WHM, DirectAdmin, related components). It ships a
core engine, pluggable vulnerability modules, scanners, JSON/HTML reporting, a
CLI, and a Textual TUI. A future desktop GUI is stubbed.

## Install

```bash
pip install -e ".[tui]"
```

## CLI

```bash
python -m cpointed scan --host 127.0.0.1 --port 2083 --fingerprint
python -m cpointed scan --targets-file targets.txt --json-out report.json --html-out report.html
cpointed tui
```

Exploit hooks are **gated** (e.g. `CPOINTED_AUTHORIZED=1` for research modules that implement `exploit()`).

## Legal

Use only on systems you own or have **explicit permission** to test. Unauthorized
use is illegal. Included remediation/stub persistence code is for defensive
workflows under the same rules.

## Contributing

See `CONTRIBUTING.md`.
