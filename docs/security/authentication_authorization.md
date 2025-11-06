# Authentication, Authorization, and Administrative Hardening

## 3. Credential Governance
- Default passwords are rotated through `setup.sh` prompts; deployment guide enforces custom admin secrets.
- Passwords stored using Django's PBKDF2 hasher with configurable iteration counts.
- MFA and SSO endpoints integrate with OAuth2/OpenID Connect (`/auth/oidc/login/`).

## 6. Administrative Interface Controls
- `/admin/` restricted via IP allowlist (`MOBSF_ADMIN_IP_RANGES`).
- Audit trails written to `logs/audit.log` with user, action, timestamp, IP.

## 35-40. Login UX & Branding
- Templates use `BrandingConfig` context processor with i18n support for English/Portuguese.
- UI texts translated via `django.po` locale files. Theme customization provided through env vars (`MOBSF_BRAND_*`).
- Login onboarding wizard described in `docs/security/onboarding_tour.md`.

## 24. Access Governance
- Merge approvals enforced in `CODEOWNERS`.
- `docs/security/governance.md` lists reviewer rotations and incident contacts.

## 25. Auditability
- Commits reference Jira tickets; `docs/security/audit_trail.md` describes evidence collection.
