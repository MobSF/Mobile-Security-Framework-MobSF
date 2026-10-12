# Delivery roadmap

## Foundation and vertical MVP

Delivered: audited integration paths; essential startup/container fixes;
separate Django app and migration; passive report import; core P0 workflow with
UI, session API, persistence and synthetic tests. See BUGBOUNTY_MODULES.md for
specific incomplete requirements. This is a usable vertical slice, not all
phases of the proposed product.

## Next stabilization work

The standalone edition now includes the Windows x64 Docker launcher, verified
Android 17 SDK metadata, a compiled manifest fixture and modern root capability
diagnostics. Full device and Windows Desktop validation is still pending.

1. Validate complete Windows Docker Desktop/WSL2 and Linux Compose lifecycle.
2. Add screenshot evidence with image decoding, size/pixel limits and privacy
   review, scoped artifact access and safe filesystem storage.
3. Add direct dynamic-report adapters and host/path fragment extraction with
   explicit inference labels. Preserve observed HTTP method evidence.
4. Add shared project roles and authorization expiry/device restrictions.
5. Retrofit secret masking into legacy core persistence and exports with
   migration/backward-compatibility tests.

## Advanced modules

Evidence-backed authentication/deep-link mapping, manual API test cases and
Burp imports, complete report templates/PDF, then confidence-aware SCA, OSV and
React Native/Hermes. No automatic credential validation or aggressive scans.
Any future active executor needs explicit scope approval, redirect revalidation,
DNS/IP restrictions, bounded rates, concurrency and audit events.

## Performance

Current imports deduplicate by artifact/program and resource/finding identity;
manual states persist across repeated imports. Core analysis is reused instead
of reexecuted. Remaining work: collect comparable application benchmarks and
query counts, avoid inventory N+1 evidence queries, bulk import where safe, and
measure artifact/storage growth. No performance improvement is claimed.
