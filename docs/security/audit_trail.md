# Audit Trail and Logging Enhancements (9, 25, 32)

- **Application Logs** – Structured JSON logs emitted via `LOGGING` configuration to `logs/app.json`.
- **Security Events** – Authentication attempts, role changes, plugin uploads logged to `logs/security.json`.
- **Retention** – Logs archived to S3 bucket with lifecycle policy (365 days hot, 365 days cold).
- **Dashboard** – Kibana dashboard `MobSF Security Posture` visualises trends and anomalies.
- **Hash Tracking** – Each upload records SHA-256/SHA-1/MD5 to support forensic replay.
