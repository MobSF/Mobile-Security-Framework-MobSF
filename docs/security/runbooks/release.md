# Release Runbook

1. Ensure `main` is green in CI and security workflows.
2. Run `scripts/dependency_audit.sh` and `scripts/secret_scan.sh`.
3. Execute `scripts/run_mastg_suite.sh`.
4. Update `CHANGELOG.md` via `scripts/update_changelog.py`.
5. Build container image, sign with `cosign`, push to registry.
6. Publish release notes referencing MASVS controls addressed.
