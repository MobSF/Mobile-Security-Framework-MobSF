# Flutter Security Framework — Requirements

Status: v0.2 — decisions recorded (2026-10-23) · Owner: Mayank Yadav
Base: fork of MobSF (`captainrogers69/Mobile-Security-Framework-MobSF`)

---

## 1. Problem

MobSF treats Flutter apps like generic native apps. Today its only Flutter
awareness is Dart detection in `mobsf/StaticAnalyzer/views/common/binary/elf.py`
(used to suppress irrelevant ELF hardening findings). The actual app logic lives in
the Dart AOT snapshot (`libapp.so` / `App.framework`), which MobSF does not parse.
Result: Flutter scans miss secrets, endpoints, plugins, pinning, storage and
platform-channel issues, and dynamic analysis breaks because Flutter ignores the
system proxy and user CA store.

## 2. Decision: salvage vs. new

**Decision (2026-10-23): salvage — extend the fork. Open source under GPL-3.0,
with the goal of contributing the Flutter work back to upstream MobSF (section 4a).**

| | Extend MobSF fork | New project |
|---|---|---|
| Upload, unpack, manifest/plist, ELF/Mach-O, report, API, auth, Docker | reused | rebuild from zero |
| Android/iOS checks for the non-Dart layer (Kotlin/Swift, manifest) | reused | rebuild |
| Time to first useful Flutter scan | weeks | months |
| Upstream security fixes | can merge from upstream | none |
| License | **GPL-3.0 stays** (derivative work) | free to choose |
| Codebase weight | large Django monolith | lean |

Flutter apps are still APK/IPA files with a Java/Kotlin/Swift shell, so most
MobSF analysis still applies. Add a dedicated `Flutter` analysis module on top.

**GPL-3.0 note:** if the product is distributed (shipped to customers, on-prem
installs), modified source must be offered under GPL-3.0. Internal-only or hosted
use has fewer obligations, but confirm with legal before commercial use.
→ Open question Q1.

## 3. Execution order

1. **Git setup** — repo, remotes, branches, CI (section 4)
2. **Services & credentials** — secrets, API keys, registry (section 5)
3. **Flutter framework** — phased delivery (section 6–8)

## 4. Git setup requirements

- G1. `origin` = our fork `captainrogers69/Mobile-Security-Framework-MobSF`
  (public; stays here per Q2).
- G2. `upstream` = `MobSF/Mobile-Security-Framework-MobSF` to pull upstream
  security fixes. Merge upstream into our `master` on a fixed cadence (e.g. monthly).
- G3. Branching: `master` mirrors upstream + our merged work; features on
  `feat/flutter-*` branches via PR. Protect `master` (PR + green CI required).
- G4. Keep Flutter code isolated in its own package
  (`mobsf/StaticAnalyzer/views/flutter/`, `mobsf/DynamicAnalyzer/tools/frida_scripts/flutter/`)
  to minimise merge conflicts with upstream.
- G5. CI (GitHub Actions): `tox -e lint`, unit tests, Docker build on every PR.
  Reuse upstream workflows (`mobsf-test.yml`, `docker-test.yml`); enable Actions on the fork.
- G6. Repo visibility: public fork (decided, Q2).

## 4a. Upstream contribution requirements

Goal: get the Flutter work merged into upstream MobSF later.

- U1. Open a feature-request issue upstream before the first PR to confirm the
  maintainers want it and agree on scope/layout.
- U2. Ship as small, focused PRs (one per phase or per check group), not one large PR.
  Each PR branches from a fresh `upstream/master`.
- U3. Follow `.github/CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`, `CLAUDE.md`
  and `AGENTS.md`; `tox -e lint` and upstream CI must pass.
- U4. Every bundled or required third-party tool must be GPL-3.0-compatible.
- U5. Keep fork-only files (`requirements.md`, `progress.md`, fork CI tweaks) out of
  upstream PRs.
- U6. No breaking changes to existing scan output, API responses or DB schema without
  a migration.

## 5. Services & credentials requirements

- S1. No secrets in git. Use `.env` (gitignored) locally and GitHub Actions secrets in CI.
  Add a secret scanner (e.g. gitleaks) to CI.
- S2. Inventory of credentials:

| Service | Purpose | Needed in | Required? |
|---|---|---|---|
| GitHub (deploy key / PAT) | repo, CI, releases | CI | yes |
| Container registry (GHCR / Docker Hub) | publish Docker image | CI | yes |
| VirusTotal API key | existing MobSF feature (`MOBSF_VT_API_KEY`) | runtime | optional |
| OSV.dev | pub.dev package vuln lookup | runtime | no key needed |
| MobSF API key | REST API auth | runtime | auto-generated |
| Django `SECRET_KEY`, DB creds (if Postgres) | app runtime | runtime | yes |
| Test device / emulator / Corellium | dynamic analysis | lab | per Q5 |

- S3. All runtime config via `MOBSF_*` environment variables, documented in one place.

## 6. Functional requirements — Flutter analysis

### 6.1 Detection & fingerprinting (P0)
- F1. Detect Flutter in APK/AAB/IPA: `libflutter.so`, `libapp.so`,
  `Flutter.framework`, `App.framework`, `flutter_assets/`.
- F2. Identify build mode: **debug/JIT** (`kernel_blob.bin`, `isolate_snapshot_data`
  in assets → source effectively recoverable → High finding) vs. release/AOT.
- F3. Extract Flutter engine version and Dart SDK version (snapshot hash);
  flag engine versions with known CVEs.
- F4. Detect obfuscation (`--obfuscate`) and missing `--split-debug-info`.
- F5. Per-ABI handling: analyse every `libapp.so` across split APKs and ABIs
  (same split-APK concern as fixed in c78bf022).

### 6.2 Dart AOT snapshot static analysis (P0/P1)
- F6. String extraction from `libapp.so` / `App.framework` → secrets, API keys,
  URLs, IPs, Firebase/Supabase/AWS configs (reuse MobSF secret regexes).
- F7. Symbol/object-pool recovery (class, function, library names) using a
  snapshot parser (candidates: blutter, reFlutter, Doldrums — evaluate license
  compatibility with GPL-3.0 and Dart-version coverage) (Q4).
- F8. Package inventory: recovered `package:` URIs → list of pub packages + versions
  where derivable.
- F9. Asset audit: `flutter_assets/` (.env files, JSON configs, certs, keys,
  `AssetManifest`, fonts excluded).

### 6.3 Flutter-specific security checks (P1)
- F10. Insecure storage: `shared_preferences`, `hive`, `sqflite` without encryption
  vs. `flutter_secure_storage`.
- F11. TLS / pinning: detect pinning packages (`http_certificate_pinning`,
  `dio` `badCertificateCallback`, `SecurityContext`), flag `badCertificateCallback`
  returning true.
- F12. Platform channels: enumerate `MethodChannel` / `EventChannel` names and
  native handlers (Kotlin/Swift side) → attack surface map.
- F13. WebView plugins (`webview_flutter`, `flutter_inappwebview`): JS enabled,
  JS bridges, file access, arbitrary URL loading.
- F14. Root/jailbreak/tamper detection presence (`flutter_jailbreak_detection`,
  `freerasp`, etc.).
- F15. Deep links / `go_router` / `uni_links` routes vs. manifest/plist intent filters.
- F16. Logging of sensitive data (`print`, `debugPrint`, `log` in release).
- F17. Map every finding to OWASP MASVS v2 + CWE.

### 6.4 Source-ZIP flow (P1)
- F18. Accept Flutter project ZIP (`pubspec.yaml` at root).
- F19. `pubspec.lock` dependency audit against OSV (pub ecosystem) — CVEs, discontinued
  packages, git/path dependencies.
- F20. Dart SAST rules (semgrep/libsast) covering F10–F16 on source.
- F21. Native shell (`android/`, `ios/`) analysed with existing MobSF rules.

### 6.5 Dynamic analysis (P2)
- F22. Traffic interception for Flutter: Frida script hooking BoringSSL
  `ssl_verify_peer_cert` / `session_verify_cert_chain` in `libflutter.so`
  (pattern-scan per engine version), plus transparent proxy (iptables) since
  Flutter ignores system proxy.
- F23. Platform-channel tracing (hook `MethodChannel` invoke on native side).
- F24. Runtime storage dump (shared_prefs, secure storage, hive boxes).
- F25. Android first; iOS behind a flag (Q5).

### 6.6 Reporting & API (P0 for whatever ships)
- F26. Dedicated "Flutter" section in HTML/PDF/JSON report.
- F27. REST API parity for every new feature.
- F28. Scan comparison between app versions (diff findings).

## 7. Non-functional requirements

- N1. Security: follow `CLAUDE.md` — all APK/IPA/ZIP/snapshot data is attacker-controlled.
  External parsers (blutter etc.) run as subprocess with list args, timeouts,
  memory caps, and ideally a sandboxed container. No `shell=True`.
- N2. Snapshot parsers that compile per-Dart-version must cache builds and fail
  gracefully (scan still completes, finding "Dart snapshot not parsed: version X").
- N3. Performance: Flutter stage adds ≤ 2 min to a typical 50 MB APK static scan.
- N4. Docker image remains the primary deployment; new tools baked in.
- N5. Test corpus: ≥ 10 sample Flutter apps (debug, release, obfuscated, multiple
  Dart versions, Android + iOS) with expected findings, run in CI.
- N6. `tox -e lint` clean; unit tests for every check.

## 8. Phases

| Phase | Scope | Exit criteria |
|---|---|---|
| 0 | Git + CI + credentials (sec. 4–5) | PR to master passes CI; image builds |
| 1 | F1–F6, F9, F26–F27 | Flutter detected, mode/version, strings & secrets in report |
| 2 | F7–F8, F10–F17, F29 | Symbols recovered for supported Dart versions; checks mapped to MASVS |
| 3 | F18–F21 | Source ZIP scan with OSV dependency audit |
| 4 | F22–F25 | Intercept HTTPS of release Flutter app on Android emulator |
| 5 | F28, iOS dynamic, hardening | Version diff; iOS parity |

## 9. Decisions (answered 2026-10-23)

- Q1. Distribution: reuse MobSF, open source under GPL-3.0, contribute upstream.
- Q2. Repo: keep the current public fork.
- Q3. Platform: Android first, iOS after.
- Q4. Third-party snapshot parsers (blutter/reFlutter/Doldrums) allowed, subject
  to U4 (GPL-3.0-compatible license).
- Q5. Dynamic lab: yes to the lab options — start on Android emulators, add physical
  rooted/jailbroken devices and Corellium when needed. *(interpretation — confirm)*
- Q6. Users: both pentesters and dev CI → add CLI + SARIF output (F29).

## 10. Added from decisions

- F29. CLI entry point and SARIF report output for CI pipelines (P2).
