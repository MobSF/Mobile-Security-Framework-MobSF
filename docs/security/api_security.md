# API Exposure and Protection (4)

- Endpoint inventory generated via `scripts/api_inventory.py` (see repo).
- Input validation enforced through DRF serializers with `validators.RegexValidator` for high-risk fields.
- Rate limiting: `django-ratelimit` configured at 100 requests/min per IP for unauthenticated, 500 for authenticated.
- CSRF enabled on all session-based endpoints; token rotation after login.
- Command injection prevention: no shell access exposed via APIs; file handling uses `pathlib.Path` with sandbox root.
