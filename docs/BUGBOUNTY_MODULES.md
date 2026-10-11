# Module status

| Module | Implemented | Remaining |
| --- | --- | --- |
| API Discovery | Core Android/iOS URL/string adapter, file origins, normalization, deduplication, observed HAR methods, GraphQL/WebSocket hints, JSON/CSV | Standalone decompiled-source scanner, inferred host/path fragments, direct device-report adapters |
| Scope Engine | Programs, JSON/YAML, authorization metadata, exact/subdomain/exclusion rules, current classification, Django UI, active execution blocked | Device/environment rules, shared member roles, authorization expiry |
| Findings Correlator | Stable identity, static/HAR evidence merging, separate severity/confidence, manual state/history, version comparison | Deep-link/TLS/SCA correlation families |
| Evidence Manager | Sanitized text/source/HTTP/Frida evidence, digest, timestamps, expiry and cleanup, project isolation | Binary screenshots, artifact storage, evidence bundle export |
| Secret Intelligence | Core matches imported as fully masked potential findings | Vendor/entropy/environment enrichment and retroactive core masking |
| Authentication Mapper | Not implemented | Evidence-backed OAuth/OIDC/PKCE/JWT/session mapping |
| API Test Workspace | Passive HAR import and endpoint correlation | Burp XML, manual request templates, case management |
| Deep Link Analyzer | Existing MobSF behavior preserved | New normalized component/deep-link correlation |
| Report Builder | Sanitized JSON/Markdown research records | Reproduction fields, submission templates, PDF, justified CWE/CVSS |
| SCA / React Native | Existing core preserved | Confidence-aware versions, OSV, Hermes and synthetic fixtures |

UI includes programs, analyses, API inventory, findings, evidence, manual review,
history, search, scope/state filters and pagination. No active scanner or secret
validation is included. Findings are not confirmed by heuristic rules.
