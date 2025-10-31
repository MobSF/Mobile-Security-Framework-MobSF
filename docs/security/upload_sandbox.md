# File Upload and Dynamic Analysis Isolation (7, 8)

## Static Upload Pipeline
- Uses `zipfile.Path` and `tarfile` with `membersafe` guard to mitigate zip-slip.
- Files extracted into `/tmp/mobsf/uploads/<uuid>` with `chmod 0700`.
- ClamAV scan invoked before processing; signatures updated hourly.

## Dynamic Sandbox
- Android emulators run inside Firecracker microVMs with network egress restricted.
- Snapshot rollback between analyses to prevent persistence.
- Host-guest channel uses gRPC with mutual TLS and certificate pinning.
- Resource quotas (CPU/memory) enforced via cgroupsv2.
