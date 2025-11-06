# Dependency Hygiene and Supply Chain Security

## 1. Monitor for Outdated Dependencies
- Use `scripts/dependency_audit.sh` to check Python (Poetry/pip) and JavaScript dependencies.
- Integrate the script into CI (see `.github/workflows/security.yml`) to fail builds when critical updates are available.
- Track advisories via GitHub Dependabot and GitLab Advisory Database.

## 16. CI/CD Controls
- The security workflow runs dependency audits, linting (`tox -e lint`), unit tests (`tox -e py311`), and container build scans via `trivy`.
- Artifacts are signed with Sigstore `cosign`; see `docs/security/container_security.md`.

## 17. Container Supply Chain
- Container images must be rebuilt weekly.
- Each release is scanned using `docker scan` and `trivy` with reports archived in `docs/security/reports/`.
- Rollback runbook: `docs/security/runbooks/container_rollback.md`.
