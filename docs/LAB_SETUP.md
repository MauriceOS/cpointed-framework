# cpointed Lab Environment (Vulnerable cPanel + WordPress)

# Made by Sn0w8ird

This document supports **authorized** lab testing of CVE-2026-41940-class chains and WordPress CVE primitives. **Do not** aim tooling at systems without written permission.

## Legal

**Legal use only:** This framework is for **authorized** security assessments and blue-team defense. **Unauthorized use is prohibited.** All exploitation requires **explicit permission** and **`CPOINTED_AUTHORIZED=1`**.

## Prerequisites

- Docker & Docker Compose
- ~16GB RAM recommended for heavy stacks (cPanel-style VMs often need several GB)
- Linux host often simplest (macOS/Windows: Docker Desktop or a Linux VM)

## ⚠️ cPanel container images

Official **cPanel/WHM** is commercial software. **Public Docker Hub images** claiming a specific build (e.g. `vimagick/cpanel:11.110.0.96`) may be **unofficial, outdated, or unavailable**. **You** must verify **license compliance**, image **provenance**, and **legality** before use. Prefer **vendor-approved** trials, snapshots, or internal golden images documented under your org’s naming convention.

The `cpanel` service block below is an **example layout** only — replace `image:` with whatever your org’s legal lab registry provides.

## Build & run (example)

```bash
git clone https://github.com/MauriceOS/cpointed-framework.git
cd cpointed-framework
# Place a compose file in your private lab repo; see example snippet below.
docker compose -f docker-compose.lab.yml up -d
```

### Access (example targets — replace with your lab matrix)

| Service | URL | Notes |
|--------|-----|--------|
| WHM / cPanel (lab) | `https://localhost:2087` | Credentials from **your** image/docs — often **not** `root`/static passwords |
| WordPress | `http://localhost:8080` | Create admin during web install; do **not** use `admin`/`admin` in real environments |

## Example `docker-compose.lab.yml`

```yaml
version: "3.8"
services:
  # Replace with a LICENSED / APPROVED lab image name from your org
  cpanel:
    image: YOUR_REGISTRY/cpanel-lab:11.110-training  # example placeholder only
    container_name: cpanel-lab
    ports:
      - "2087:2087"
      - "2083:2083"
    environment:
      - CPANEL_LAB_PASS=ChangeMeOnFirstBoot
    volumes:
      - ./cpanel-data:/var/cpanel

  wordpress:
    image: wordpress:6.0
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_NAME: wp
      WORDPRESS_DB_USER: wpuser
      WORDPRESS_DB_PASSWORD: wp123
    depends_on:
      - db
    volumes:
      - ./wp-content:/var/www/html/wp-content

  db:
    image: mariadb:10.7
    environment:
      MYSQL_DATABASE: wp
      MYSQL_USER: wpuser
      MYSQL_PASSWORD: wp123
      MYSQL_ROOT_PASSWORD: root123
```

## After WordPress starts — pin vulnerable plugins (lab only)

Use **WP-CLI** inside the container when available; versions are **examples** — align with your advisory:

```bash
docker exec -it wordpress bash -lc "wp plugin install wpvivid-backuprestore --version=0.9.123 --activate --allow-root || true"
docker exec -it wordpress bash -lc "wp plugin install kivicare --version=1.2.3 --activate --allow-root || true"
```

## Exploit steps (authorized)

```bash
export CPOINTED_AUTHORIZED=1
export CPOINTED_SSH_PUBKEY="$(cat ~/.ssh/id_rsa.pub 2>/dev/null || echo 'ssh-ed25519 ...')"
```

### cPanel chain (adjust host/port)

```bash
python -m cpointed exploit --cve CVE-2026-41940 --host 127.0.0.1 --port 2087 --ssl
```

### WordPress primitives

Set **`CPOINTED_KIVICARE_LAB_JWT`** for KiviCare REST tests when your PoC supplies a JWT.

```bash
python -c "import asyncio,os; os.environ['CPOINTED_AUTHORIZED']='1'; from cpointed.core.engine import Target; from cpointed.modules.wordpress.cve_2026_1357_wpvivid import CVE20261357WPvivid; print(asyncio.run(CVE20261357WPvivid().exploit(Target('127.0.0.1',8080,False))))"
```

### Remediate (SSH to lab host)

```bash
python -m cpointed.remediation.cleaner 127.0.0.1 root ~/.ssh/admin_key --auto-patch
```

## Cleanup

```bash
docker compose -f docker-compose.lab.yml down -v
```

## Environment variables (reference)

| Variable | Role |
|----------|------|
| `CPOINTED_AUTHORIZED=1` | Mandatory gate for exploit / persistence / cleaner |
| `CPOINTED_SSH_PUBKEY` | WHM Fileman SSH key tests |
| `CPOINTED_KIVICARE_LAB_JWT` | KiviCare login PoC token (lab) |
| `CPOINTED_GEEKYBOT_INSTALL_URL` | Geeky Bot install ZIP URL (lab); default is non-routable |
| `CPOINTED_PAYLOAD_DIR` | Operator payload bundle root |
