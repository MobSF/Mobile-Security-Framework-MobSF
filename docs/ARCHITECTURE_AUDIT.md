# Architecture audit — MobSF Bug Bounty Edition

Baseline: MobSF 4.5.4, commit `7a4785fb`, Python 3.12–3.13, Django,
Poetry 1.8.4, GPL-3.0-only. Existing credits and license are preserved.

## Inspected integration paths

StaticAnalyzer stores Android/iOS/Windows results in separate models. Its
`db_interaction.py` adapters expose URLs with source paths, strings, secrets,
manifest findings and SBOM. DynamicAnalyzer uses external devices, Frida and
traffic reports. MobSF owns settings, authentication, roles and REST middleware.
There are 121 view files in the relevant directories. This audit covers the
integration and configuration paths; it is not a claim of line-by-line review
of the entire repository. Neither bb_workspace nor a starter archive exists.

## Confirmed findings

| Priority | Evidence | Resolution |
| --- | --- | --- |
| P0 | `scripts/entrypoint.sh`: `--log-level=citical` | Corrected to `critical`. |
| P0 | `docker/docker-compose.yml`: fixed database password | External password required without fallback. Named persistent volumes. |
| P0 | Same Compose: `latest` images | Versioned PostgreSQL/nginx; locally built fork image. |
| P0 | `settings.py`: wildcard ALLOWED_HOSTS | Local hosts by default; explicit MOBSF_ALLOWED_HOSTS override. |
| P0 | `utils.print_version()`: REST key printed at startup | Key output removed; existing API authentication remains supported. |
| P0 | Dockerfile: default administrator password | Removed; explicit password required at startup. |
| P0 | Dockerfile regenerates lockfile during build | Install the committed lockfile. |
| P1 | Standalone downloader imports package absent during image build | Copy minimal package and exception files before running downloader. |
| P0 | dependencies.sh ignores failed JDK download | Use Java 21 from signed Debian 13 packages; fail on missing required tools. |
| P0 | `secret_detection.py`, SECRETS model fields and adapters retain complete values | New workspace masks before persistence; retroactive core cleanup remains pending. |
| P1 | `sbom_analysis.py` uses .version files and package names | Preserve core; confidence-aware SCA extension remains pending. |
| P0 | Global REST key does not identify a project owner | New JSON API uses Django session, CSRF and project ownership. |

## Architecture decisions and limits

New Django app BugBounty, no additional service. Each record belongs to a
program; its owner and platform superusers can access it. Import explicitly
consumes a completed, persisted MobSF report, without running analysis or
network calls. Heuristic findings start NEW, never CONFIRMED. Scope classification
does not enable traffic: no active executor exists in this release.

Evidence supports sanitized source references, text, Frida logs and HTTP
metadata. Binary screenshots, Burp XML, and automatic device-report adapters
remain pending. HAR import is passive and bounded. Archives are not extracted
by the new app. Private inputs and reports must never enter commits.

The original regression suite performs external lookups; run it offline with
both process proxies and MobSF upstream proxy pointing to an unavailable local
port. No TLS or checksum checks were disabled during setup.

## Current machine

Python 3.12.14 and Java 21; 106 locked dependencies installed. SQLite migrations
and Django system checks passed. JADX 1.5.0 required writable XDG_CONFIG_HOME;
setting it under /workspace fixed decompilation. wkhtmltopdf 0.12.6.1 with
patched Qt is installed locally. See TEST_RESULTS.md for final evidence.
