# cpointed Lab Environment

Docker-based lab for testing cPanel/WHM and WordPress CVE modules against controlled targets. All lab work must target systems you own or have explicit written authorization to test.

## Prerequisites

- Docker and Docker Compose
- Linux host (or Docker Desktop on macOS/Windows)
- ~8 GB free RAM for a cPanel + WordPress stack

## cPanel images

cPanel/WHM is commercial software. Public container images are unofficial and may be outdated. Use a vendor-approved trial image or your organization's internal lab image and replace `image:` in the example below with your registry path.

## docker-compose.lab.yml

```yaml
version: "3.8"
services:
  cpanel:
    image: YOUR_REGISTRY/cpanel-lab:training   # replace with your licensed image
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

```bash
docker compose -f docker-compose.lab.yml up -d
```

Default access:

| Service | URL |
|---------|-----|
| WHM | `https://localhost:2087` |
| cPanel | `https://localhost:2083` |
| WordPress | `http://localhost:8080` |

## Install vulnerable WordPress plugins (lab only)

Versions below match the CVE advisory ranges; adjust as needed:

```bash
docker exec -it wordpress bash -lc "wp plugin install wpvivid-backuprestore --version=0.9.123 --activate --allow-root"
docker exec -it wordpress bash -lc "wp plugin install kivicare --version=1.2.3 --activate --allow-root"
```

## Running modules

```bash
export CPOINTED_AUTHORIZED=1
export CPOINTED_SSH_PUBKEY="$(cat ~/.ssh/id_rsa.pub)"

# cPanel/WHM
cpointed exploit --cve CVE-2026-41940 --host 127.0.0.1 --port 2087 --ssl

# WordPress
cpointed exploit --cve CVE-2026-1357 --host 127.0.0.1 --port 8080 --no-ssl
```

Set `CPOINTED_KIVICARE_LAB_JWT` when your KiviCare PoC requires a JWT.

## Remediation

```bash
# Print checklist only
cpointed remediate --plan-only

# Execute over SSH (requires CPOINTED_AUTHORIZED=1 and paramiko extra)
python -m cpointed.remediation.cleaner 127.0.0.1 root ~/.ssh/lab_key
```

## Cleanup

```bash
docker compose -f docker-compose.lab.yml down -v
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `CPOINTED_AUTHORIZED=1` | Required gate for exploit and persistence operations |
| `CPOINTED_SSH_PUBKEY` | SSH public key for WHM Fileman tests |
| `CPOINTED_KIVICARE_LAB_JWT` | JWT token for KiviCare REST PoC |
| `CPOINTED_GEEKYBOT_INSTALL_URL` | Plugin ZIP URL for Geeky Bot install test |
| `CPOINTED_PAYLOAD_DIR` | Operator payload bundle root directory |
