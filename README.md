# cpointed

**Owner:** Sn0w8ird · **License:** MauriceOS (see `LICENSE`)

## Legal (read first)

**Legal use only:** This framework is for **authorized** security assessments, **blue-team** defense, and **controlled research**. **Unauthorized access to computer systems is illegal.** All exploitation and persistence features require **explicit written permission** from the system owner and the environment variable **`CPOINTED_AUTHORIZED=1`**. Using this software outside a lawful scope is prohibited; you are responsible for compliance with applicable laws and contracts.

See also `docs/LAB_SETUP.md` for a defensive lab workflow.

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
# Or: python -m cpointed.cli.main scan ...
cpointed tui
```

Exploit hooks are **gated** (e.g. `CPOINTED_AUTHORIZED=1` for research modules that implement `exploit()`).

## Contributing

See `CONTRIBUTING.md`.
