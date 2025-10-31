# Repository Governance and Access Control

## Merge Controls (24)
- `CODEOWNERS` requires review from Core Security team for `/mobsf/` and `/docs/security/`.
- Branch protection rule `main`: status checks (`ci`, `security`), signed commits, linear history.

## Security Response Policy (23)
- Vulnerability reports: security@befly.com, PGP key fingerprint `A1B2 C3D4 E5F6`.
- SLA: triage within 24h, fix critical issues within 7 days.
- Public disclosure via SECURITY.md updates.

## Audit and Traceability (25)
- Release notes appended to `CHANGELOG.md` with CVE references.
- Incident reviews stored in `docs/security/postmortems/` with action items tracked in Jira.
