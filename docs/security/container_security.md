# Runtime Hardening and Container Security (5, 17)

- Base image: `python:3.11-slim` hardened with `useradd mobsf` and non-root execution.
- Linux capabilities dropped via `docker-compose.yml` (`cap_drop: [ALL]`).
- Read-only root filesystem with named volumes for uploads and logs.
- TLS termination handled by Traefik with automatic Let's Encrypt.
- At-rest encryption: uploads stored on encrypted volume (LUKS) or S3 SSE-KMS.
- Network policies restrict outbound traffic from dynamic analysis sandbox to update mirrors only.
