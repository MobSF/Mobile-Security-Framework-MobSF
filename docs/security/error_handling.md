# Secure Error Handling (12)

- User-facing errors use generic messaging with unique incident IDs.
- Detailed stack traces logged to `logs/debug.log` accessible only to admins.
- Django `DEBUG=False` in production; custom `handler500` renders sanitized template.
- Sensitive data scrubbed via logging filter `mobsf.logging.SensitiveDataFilter`.
