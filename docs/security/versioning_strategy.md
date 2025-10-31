# Versioning and Release Management (15, 20)

- Semantic versioning `MAJOR.MINOR.PATCH` with pre-release tags for betas.
- Release branches `release/x.y` cut from `main`; hotfixes from latest tag.
- `CHANGELOG.md` updated via `scripts/update_changelog.py` referencing security fixes.
- Tags signed (`git tag -s`).
- Release checklist in `docs/security/runbooks/release.md`.
