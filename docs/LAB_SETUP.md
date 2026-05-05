# cpointed Lab Setup (Authorized Testing Only)

# Made by Sn0w8ird

This document describes how to run a **defensive / purple-team style lab** for validating **cpointed** scans, exploit hooks, and remediation — **not** for unauthorized targets.

## Legal disclaimer

**Legal use only:** This framework is for **authorized** security assessments and blue-team defense. **Unauthorized use is prohibited.** All destructive operations require **explicit written permission** from the system owner and the environment variable **`CPOINTED_AUTHORIZED=1`**.

## Required environment variables

| Variable | Purpose |
|---------|---------|
| `CPOINTED_AUTHORIZED=1` | Gate for exploit chains, persistence, and remote remediation. |
| `CPOINTED_SSH_PUBKEY` | Your single-line OpenSSH **public** key for WHM Fileman SSH tests (CVE chain). |
| `CPOINTED_PAYLOAD_DIR` | Optional operator bundle root (see `cpointed.payloads`). |
| `CPOINTED_WP_AUDIT_USER` / `CPOINTED_WP_AUDIT_EMAIL` | Optional WordPress registration probe identity. |

## WordPress + WPvivid (e.g. 0.9.123) — Docker

Official **cPanel/WHM** is not redistributable as a simple public **Docker Compose** image aligned to **11.110.0.96**. For plugin-level validation, use a **WordPress** stack and install a **specific WPvivid** zip from your **vendor-approved** archive.

Example `docker-compose.yml` (WordPress only — **adjust versions and passwords**):

```yaml
services:
  db:
    image: mariadb:10.11
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp
      MYSQL_PASSWORD: changeme
      MYSQL_ROOT_PASSWORD: rootchangeme
    volumes:
      - db_data:/var/lib/mysql

  wordpress:
    image: wordpress:6.5-php8.2-apache
    depends_on:
      - db
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: changeme
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wp_html:/var/www/html

volumes:
  db_data:
  wp_html:
```

### Install pinned WPvivid (example)

1. Start compose: `docker compose up -d`
2. Complete the WordPress web installer at `http://127.0.0.1:8080`
3. Install **WPvivid Backup** from a **zip you obtained lawfully** (e.g. vendor archive of **0.9.123** for a **lab**).

### Run cpointed against the lab

```bash
export CPOINTED_AUTHORIZED=1
python -m cpointed wp scan --host 127.0.0.1 --port 8080 --ssl --path /
python -m cpointed scan --host 127.0.0.1 --port 8080 --no-ssl --wordpress --json-out out.json
```

### Exploit primitive (authorized)

After confirming scope, trigger the module exploit (records **real HTTP** for reporting):

```bash
python -c "import asyncio,os; os.environ['CPOINTED_AUTHORIZED']='1'; from cpointed.core.engine import Target; from cpointed.modules.wordpress.cve_2026_1357_wpvivid import CVE20261357WPvivid; print(asyncio.run(CVE20261357WPvivid().exploit(Target('127.0.0.1',8080,False))))"
```

Tune **`exploit_remote_primitive`** field names to your **verified PoC** if the plugin build differs.

### Remediate and verify

1. **Upgrade** WPvivid to a **patched** vendor release (or remove the plugin).
2. Re-run **`wp scan`** and compare JSON/HTML reports.
3. For **host cleanup** after a full engagement (SSH access assumed):

```bash
export CPOINTED_AUTHORIZED=1
python -m cpointed.remediation.cleaner <host> <ssh_user> <path_to_key> [--auto-patch]
```

## cPanel / WHM (11.110.0.96-class builds)

Use a **licensed** cPanel environment (VM, cloud image, or vendor trial) permitted for security testing. There is **no** endorsed public Compose recipe for full **cPanel 11.110.0.96** in this repo; document your **internal** image name and snapshot IDs in the engagement folder.

Typical flow after lab provision:

1. `export CPOINTED_AUTHORIZED=1` and `CPOINTED_SSH_PUBKEY=...`
2. `python -m cpointed scan --host <whm_host> --port 2087 --fingerprint --json-out cpanel.json`
3. `python -m cpointed exploit --cve CVE-2026-41940 --host <whm_host> --port 2087 ...` (only in-scope)
4. Archive artefacts for the **organization closeout report**.

## Reporting

Capture:

- CLI JSON / HTML outputs
- Exploit return payloads (redact secrets)
- Remediation commands issued and post-patch scan diffs

Store under your engagement’s evidence policy (chain-of-custody, hashes).
