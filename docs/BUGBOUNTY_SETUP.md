# Setup and operation

GPL-3.0-only and upstream credits remain in force. Use authorized test artifacts.
This release is passive; importing a report or HAR does not contact its targets.

## Current cloud machine

Checkout: `/workspace/Mobile-Security-Framework-MobSF`. Python dependencies
are in its ignored `.venv`; runtime data and helpers are outside the checkout
under `/workspace/.mobsf-setup`. Reuse the existing isolated checkout.

```bash
cd /workspace/Mobile-Security-Framework-MobSF
source /workspace/.mobsf-setup/env.sh
poetry run python manage.py migrate
bash /workspace/.mobsf-setup/start.sh
# In another terminal, verify login page with an internal HTTP request:
curl --fail http://127.0.0.1:8000/login/ -o /tmp/mobsf-login.html
poetry run python manage.py changepassword mobsf
```

The onboarding helper generates a random local administrator password and
preserves existing accounts. It is stored with mode 0600 outside the checkout;
do not print or commit it. Use `changepassword` to choose your own password.
The cloud onboarding UI does not provide a localhost preview.

Upload an authorized APK/IPA in Static Analyzer, complete its analysis, then open
Bug Bounty Workspace. Create a program and import that scan's MD5. An empty
program remains UNKNOWN until source/date and approval are recorded. Synthetic
tests use `.test` domains; there is no need for a real bug bounty program.

## Windows 11 / Docker Desktop / WSL2

Enable WSL2 and Docker Desktop Linux containers. From PowerShell:

```powershell
git clone --branch standalone/bug-bounty-edition https://github.com/Ivomsantiago/Mobile-Security-Framework-MobSF.git
Set-Location Mobile-Security-Framework-MobSF
Copy-Item docker/.env.example docker/.env
notepad docker/.env
# Set different strong POSTGRES_PASSWORD and MOBSF_ADMIN_PASSWORD values.
docker compose --env-file docker/.env -f docker/docker-compose.yml config --quiet
docker compose --env-file docker/.env -f docker/docker-compose.yml build mobsf
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
docker compose --env-file docker/.env -f docker/docker-compose.yml logs -f mobsf
docker compose --env-file docker/.env -f docker/docker-compose.yml stop
```

Local Windows access uses port 8000. Services bind to loopback. PostgreSQL 17.6
and nginx 1.28.0 are versioned; the fork image is `mobsf-bounty:4.5.4-dev`, built
from this checkout. Pin reviewed image digests and update patch releases before
production use. An existing database's password is not changed by editing .env;
rotate it through PostgreSQL administration.

Compose uses named `postgres_data` and `mobsf_data` volumes. Never use `down -v`
when preserving data. Container startup requires an explicit administrator
password; no default password is embedded in the image. Existing users are
preserved. `mobsf`/`djangoq` run under the Dockerfile's unprivileged user. The
dynamic-analysis proxy is loopback only and is optional for the passive MVP.

## Linux source installation

Install Python 3.12 or 3.13, Java 21+, Poetry 1.8.4 and a supported wkhtmltopdf.
Use an unprivileged account. Provision a persistent writable directory:

```bash
python3.12 -m venv .tools
.tools/bin/pip install poetry==1.8.4
mkdir -p "$PWD/.data" "$PWD/.runtime/config" "$PWD/.runtime/cache"
export MOBSF_HOME_DIR="$PWD/.data"
export XDG_CONFIG_HOME="$PWD/.runtime/config"
export XDG_CACHE_HOME="$PWD/.runtime/cache"
export POETRY_VIRTUALENVS_IN_PROJECT=true
.tools/bin/poetry install --only main --no-root --no-interaction
git submodule update --init --recursive
.venv/bin/python manage.py makemigrations StaticAnalyzer
.venv/bin/python manage.py migrate
.venv/bin/python manage.py createsuperuser
.venv/bin/python manage.py create_roles
.venv/bin/gunicorn -b 127.0.0.1:8000 mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600
```

Add `.data/`, `.runtime/` and `.tools/` to `.git/info/exclude`; never commit them.
Do not run setup.sh against existing data: it includes cleanup and lock updates.
Keep TLS verification enabled for all downloads and upstream proxies.

## VPS with TLS

Run Compose on Linux with its loopback bindings. Configure a host reverse proxy
(nginx/Caddy) for your approved hostname and certificate. For example:

```caddyfile
research.example.test {
    reverse_proxy 127.0.0.1:8000
}
```

Replace the synthetic hostname with your own real domain. Set
`MOBSF_ALLOWED_HOSTS` to that hostname and local hosts, provision TLS, keep only
443 exposed, and require MobSF login. Do not expose PostgreSQL or port 1337.
Restrict network egress and disable optional core provider lookups when not
authorized. Set secure cookie flags in deployment settings; configure trusted
proxy headers only for your controlled proxy. This is a deployment example,
not a validated production deployment or an automatic certificate operation.

## Backup, recovery, update

Stop application writers before a consistent artifact backup. Back up .env
securely without including it in Git. For PostgreSQL:

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml stop mobsf djangoq
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T postgres pg_dump -U postgres -Fc mobsf > mobsf-db.dump
# Back up the mobsf_data named volume through your backup system.
# Restore to an empty database, then restore the matching artifact snapshot:
docker compose --env-file docker/.env -f docker/docker-compose.yml exec -T postgres pg_restore -U postgres -d mobsf --clean --if-exists < mobsf-db.dump
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
```

SQLite users should stop Gunicorn and copy the full MOBSF_HOME_DIR, including
database and secret, to protected backup storage. Reopen the restored database
only with a compatible application version. Rehearse restoration separately.
Schedule `manage.py purge_bounty_evidence` daily for retention cleanup.

Update the fork with a review branch, preserving history:

```bash
git remote add upstream https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
git fetch upstream
git switch -c integration/upstream-update
git merge upstream/master
# Resolve conflicts, run tests and lint, review dependency/image updates.
git push -u origin integration/upstream-update
```

Back up before updating. Build the reviewed image, run migrations and verify
login/workspace readiness before retiring the previous image. Never force push.
Windows installation and VPS/TLS restoration were not validated on those
platforms in this cloud task; see TEST_RESULTS.md for executed checks.

## Building behind the cloud egress proxy

The optional BuildKit `build_ca` secret supplies an existing trusted CA bundle
for build downloads without disabling TLS verification. It is not copied into
the final image. In this cloud machine the proxy hostname must also be resolved
explicitly for the Docker build network:

```bash
mkdir -p /workspace/.mobsf-setup/docker-config
cloud_proxy_ip=$(getent ahostsv4 proxy | awk 'NR==1 {print $1}')
DOCKER_CONFIG=/workspace/.mobsf-setup/docker-config docker build \
  --add-host "proxy:$cloud_proxy_ip" \
  --secret id=build_ca,src=/etc/ssl/certs/ca-certificates.crt \
  --build-arg HTTP_PROXY --build-arg HTTPS_PROXY \
  --build-arg http_proxy --build-arg https_proxy \
  -t mobsf-bounty:4.5.4-dev .
```

On Docker Desktop without a custom TLS proxy, ordinary Compose build commands
need no such options. The cloud daemon uses VFS storage; unused layers duplicate
large filesystem trees, so check disk capacity before building multiple images.
