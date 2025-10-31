# Environment Configuration Reference (21)

| Variable | Description | Default |
|----------|-------------|---------|
| `MOBSF_SECRET_KEY` | Django secret key | required |
| `MOBSF_ADMIN_IP_RANGES` | CIDRs allowed for admin UI | `127.0.0.1/32` |
| `MOBSF_BRAND_PRIMARY` | Primary hex colour | `#1E88E5` |
| `MOBSF_ENABLE_MFA` | Enforce MFA enrollment | `true` |
| `MOBSF_UPLOAD_QUARANTINE_DIR` | Path for ClamAV scanning | `/var/mobsf/quarantine` |
| `MOBSF_LOG_LEVEL` | Logging level | `INFO` |
| `MOBSF_ALLOWED_HOSTS` | Comma-separated hostnames | `localhost` |

Security recommendations accompany each variable; rotate secrets quarterly.
