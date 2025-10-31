# Testing Strategy (11, 26-33)

- Unit tests executed via `pytest` with coverage threshold 85%.
- Integration suite spins up Docker services to exercise API, upload pipeline, and sandbox.
- Security regression tests map to MASTG controls; see `docs/security/MASTG_mapping.md`.
- CI pipeline publishes HTML reports to `artifacts/tests/index.html`.
- Failures create Jira tickets automatically via webhook integration.
