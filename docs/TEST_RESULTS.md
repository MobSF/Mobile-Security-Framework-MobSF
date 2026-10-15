# Executed validation

Date: 2026-10-11. Native cloud runtime: Debian 13, Python 3.12.14, Java 21.
Container runtime: Debian 13, Python 3.13.16, Java 21, unprivileged mobsf user.
Tests used repository-provided authorized fixtures and synthetic `.test` data.
Application regressions and HTTP APK scans ran with external requests blocked
through both process proxies and the MobSF upstream proxy at loopback port 9.
Package installation used verified TLS and the existing locked artifact hashes.

| Check | Actual result |
| --- | --- |
| Locked Poetry installation | 106 dependencies installed; repeat run had no updates |
| Saved install instructions | Executed successfully; existing accounts and tracked changes preserved |
| Django migrations and system checks | Passed; no system issues |
| New migration consistency | `makemigrations BugBounty --check --dry-run`: no changes |
| Full `manage.py test mobsf --noinput` | 39 tests passed in 407.410 s: 37 workspace tests at that revision and 2 original integration tests |
| Final `manage.py test mobsf.BugBounty --noinput` | 38 tests passed; covers malformed methods/hosts, ambiguous routing paths and the actual core authentication-disable setting |
| `tox -e lint` | Passed, including flake8 and codespell; rerun before commits |
| Bandit on new application code | Zero reported issues; synthetic test fixtures excluded from this security scan |
| Native HTTP smoke | Login, workspace/session API, APK upload/static scan, core import, inventory, scope, exports and review passed |
| Native service restart | Analysis, endpoints, findings, evidence and review events persisted |
| Docker image build | Completed with verified proxy CA supplied through optional BuildKit secret |
| Docker functional smoke | Java 21, authenticated login, authorized APK scan, workspace import and UNKNOWN scope passed |
| Docker restart | Analyzed application, endpoints and findings persisted in the named data volume |
| Compose configuration | Parsed successfully with synthetic validation-only password inputs |
| Repository hygiene | No dependency declaration or lockfile changes; secrets/runtime data excluded from Git |

## Coverage of the new suite

Exact/subdomain boundary matching; exclusion priority; missing authorization;
IDNA; ambiguous encodings and credential URLs; unsafe YAML; active execution
blocking; path-preserving resource identity; observed HTTP methods; query-value
removal; redaction and depth limits; passive idempotent Android/iOS import;
project access isolation; CSRF; global-key bypass resistance; import permissions;
manual confirmation requirements and immutable history; HAR correlation and
rollback; request size limits; evidence retention and source validation;
HTML escaping; JSON/CSV exports; same-application version comparison; manual
finding creation, review, evidence and Markdown/JSON reports.

## Failures diagnosed and corrected

* UV initially targeted a read-only home cache; caches now live under /workspace.
* JADX attempted a read-only configuration directory; writable XDG_CONFIG_HOME
  fixed decompilation, confirmed with the real APK fixture.
* One new test serialized datetime without a JSON encoder; corrected fixture
  serialization. An additional hostname test used an invalid underscore host;
  corrected its expectations and added a valid long-label redaction case.
* Generated migration formatting, an unused import and documentation spelling
  failed lint initially; corrected without disabling checks.
* First HTTP fixture upload omitted an APK MIME type; the smoke client now
  supplies `application/vnd.android.package-archive`.
* Docker build could not resolve the cloud proxy; explicit build host mapping
  fixed it. Verified build downloads needed the existing trusted CA bundle;
  the optional BuildKit secret supplies it without disabling TLS verification.
* Original dependency script ignored a denied JDK archive download. Java 21 now
  comes from signed Debian packages, and required tools are checked explicitly.
* Multiple image attempts filled the 32 GB VFS storage. Removed only the unused
  test image/build caches, recovered 25 GB and completed a fresh build.
* The first Docker restart readiness deadline was too short for the core's
  sequential management-command startup and offline update checks. Startup
  completed, HTTP became ready, and the retained state was then verified.

## Measured baseline

Single synthetic run over 1,000 distinct endpoint references: discovery
0.431620 s, current-rule scope classification 0.151084 s, peak traced Python
allocation 1,212,459 bytes. This measures the pure normalization/scope path,
not full APK analysis or database latency. No performance improvement is claimed.

## Not executed or not implemented

Windows 11/Docker Desktop, a complete PostgreSQL/Django Q Compose deployment,
VPS TLS deployment, backup restoration drills, external active security tests,
and physical/emulated-device dynamic analysis were not executed. Docker image
and SQLite application operation were validated on this Linux cloud machine.
The initial pre-correction regression attempt was interrupted and is not counted
as a completed test run. Optional external provider lookups were blocked during
offline regressions; they were not validated.

P0 extensions and P1/P2 limitations are listed in BUGBOUNTY_MODULES.md and
ROADMAP.md. Core legacy secret persistence/exports are not retroactively
sanitized by this release. Do not describe this as a complete production audit
or all four product phases delivered.
