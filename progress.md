# Flutter Security Framework — Progress

Tracks every item in [`requirements.md`](requirements.md). Update the status,
date and notes as work lands. Last updated: 2026-10-23

**Legend:** ✅ done · 🟡 in progress · ⬜ not started · ⛔ blocked · ❓ needs decision

## Summary

| Area | Done | Total | Status |
|---|---|---|---|
| Planning | 2 | 2 | ✅ |
| Decisions | 5 | 6 | 🟡 |
| Phase 0 — Git setup | 5 | 8 | 🟡 |
| Phase 0 — Services & credentials | 0 | 3 | ⬜ |
| Upstream contribution | 0 | 6 | ⬜ |
| Phase 1 — Detection & strings | 0 | 9 | ⬜ |
| Phase 2 — Snapshot, checks, CLI | 0 | 11 | ⬜ |
| Phase 3 — Source ZIP | 0 | 4 | ⬜ |
| Phase 4 — Dynamic (Android) | 0 | 4 | ⬜ |
| Phase 5 — Diff, iOS, hardening | 0 | 1 | ⬜ |
| Non-functional | 0 | 6 | ⬜ |

---

## Planning

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| P-1 | Draft `requirements.md` | ✅ | 2026-10-23 | v0.1 |
| P-2 | Record decisions in requirements | ✅ | 2026-10-23 | v0.2 |

## Decisions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q1 | Distribution model / GPL-3.0 | ✅ | Reuse MobSF, open source GPL-3.0, upstream later |
| Q2 | Repo location and visibility | ✅ | Keep current public fork |
| Q3 | Platform priority | ✅ | Android first, iOS after |
| Q4 | Third-party snapshot parsers | ✅ | Allowed if GPL-3.0-compatible (U4) |
| Q5 | Dynamic lab | ❓ | Read as "emulators first, devices/Corellium later" — confirm |
| Q6 | Target users | ✅ | Both → CLI + SARIF (F29) |

## Phase 0 — Git setup

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| G1 | `origin` = our fork | ✅ | 2026-10-23 | `captainrogers69/Mobile-Security-Framework-MobSF` |
| G2 | `upstream` remote and merge cadence | 🟡 | 2026-10-23 | Remote set and fetched; `master` level with `upstream/master` (08872c84). Cadence TBD |
| G3 | Branching model and `master` protection | ✅ | 2026-10-23 | `feat/flutter-*` branches. `master`: PR required (0 approvals), checks `build (ubuntu-22.04, 3.12/3.13)` + `buildx`, up-to-date branch, conversations resolved, no force-push/delete, admin bypass on for upstream syncs |
| G7 | Issues enabled on fork | ✅ | 2026-10-23 | |
| G8 | `.github/CODEOWNERS` → `@captainrogers69` | 🟡 | 2026-10-23 | File created, not committed. Fork-only (U5) |
| G4 | Isolated Flutter package layout | ⬜ | | `StaticAnalyzer/views/flutter/`, `frida_scripts/flutter/` |
| G5 | CI: lint, tests, Docker build on PR | ⬜ | | Reuse upstream `mobsf-test.yml`, `docker-test.yml`; enable Actions on fork |
| G6 | Repo visibility | ✅ | 2026-10-23 | Public fork |

## Phase 0 — Services & credentials

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| S1 | `.env` + CI secrets, gitleaks in CI | ⬜ | | |
| S2 | Credentials inventory provisioned | ⬜ | | GitHub, registry, VT key, Django secret, DB |
| S3 | `MOBSF_*` env vars documented | ⬜ | | |

## Upstream contribution

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| U1 | Feature-request issue upstream | ⬜ | | Before first PR |
| U2 | Small focused PRs from `upstream/master` | ⬜ | | |
| U3 | Follow CONTRIBUTING, PR template, CLAUDE.md | ⬜ | | |
| U4 | GPL-3.0-compatible dependencies only | ⬜ | | Check blutter/reFlutter/Doldrums licenses |
| U5 | Fork-only files kept out of upstream PRs | ⬜ | | `requirements.md`, `progress.md` |
| U6 | No breaking output/API/DB changes | ⬜ | | |

## Phase 1 — Detection, fingerprinting, strings, reporting

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F1 | Detect Flutter in APK/AAB/IPA | ⬜ | | Existing: `is_dart()` in `binary/elf.py` |
| F2 | Debug/JIT vs release/AOT build mode | ⬜ | | |
| F3 | Engine + Dart SDK version, known CVEs | ⬜ | | |
| F4 | Obfuscation / split-debug-info detection | ⬜ | | |
| F5 | Every `libapp.so` across ABIs and splits | ⬜ | | |
| F6 | String extraction → secrets, URLs, configs | ⬜ | | |
| F9 | `flutter_assets/` audit | ⬜ | | |
| F26 | Flutter section in HTML/PDF/JSON report | ⬜ | | |
| F27 | REST API parity | ⬜ | | |

## Phase 2 — Dart snapshot analysis, Flutter checks, CLI

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F7 | Symbol / object-pool recovery | ⬜ | | Parser choice per U4 |
| F8 | Pub package inventory | ⬜ | | Depends on F7 |
| F10 | Insecure storage | ⬜ | | |
| F11 | TLS / pinning checks | ⬜ | | |
| F12 | Platform-channel enumeration | ⬜ | | |
| F13 | WebView plugin checks | ⬜ | | |
| F14 | Root/jailbreak/tamper detection presence | ⬜ | | |
| F15 | Deep links vs manifest/plist | ⬜ | | |
| F16 | Sensitive logging | ⬜ | | |
| F17 | MASVS v2 + CWE mapping | ⬜ | | |
| F29 | CLI + SARIF output | ⬜ | | From Q6 |

## Phase 3 — Source-ZIP flow

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F18 | Accept Flutter project ZIP | ⬜ | | |
| F19 | `pubspec.lock` OSV audit | ⬜ | | |
| F20 | Dart SAST rules | ⬜ | | |
| F21 | Native shell via existing MobSF rules | ⬜ | | |

## Phase 4 — Dynamic analysis (Android)

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F22 | Flutter TLS bypass + transparent proxy | ⬜ | | Emulators first (Q5) |
| F23 | Platform-channel tracing | ⬜ | | |
| F24 | Runtime storage dump | ⬜ | | |
| F25 | iOS dynamic behind flag | ⬜ | | After Android (Q3) |

## Phase 5 — Diff, iOS parity, hardening

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F28 | Scan comparison between versions | ⬜ | | |

## Non-functional (ongoing)

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| N1 | Sandboxed external parsers, list args, timeouts | ⬜ | | |
| N2 | Parser build cache + graceful failure | ⬜ | | |
| N3 | ≤ 2 min added per 50 MB APK | ⬜ | | |
| N4 | Tools baked into Docker image | ⬜ | | |
| N5 | Test corpus ≥ 10 Flutter apps in CI | ⬜ | | |
| N6 | `tox -e lint` clean + unit tests | ⬜ | | |

---

## Log

| Date | Change |
|---|---|
| 2026-10-23 | Created `requirements.md` v0.1 and `progress.md` |
| 2026-10-23 | Recorded Q1–Q6 decisions, added upstream contribution section (U1–U6) and F29 |
| 2026-10-23 | `upstream` remote fetched; branch `feat/flutter-planning` created |
| 2026-10-23 | Planning docs committed (72fd4cb6, not pushed); `master` protected; Issues on; CODEOWNERS added |
