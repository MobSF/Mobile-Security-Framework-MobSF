# Container Rollback Runbook

1. Identify last known-good image tag from `registry.example.com/mobsf/security`.
2. Verify signature via `cosign verify`.
3. Update deployment manifest `k8s/mobsf-deployment.yaml` with previous digest.
4. Redeploy with `kubectl rollout restart` and monitor health probes.
5. Post-incident review recorded in `docs/security/postmortems/`.
