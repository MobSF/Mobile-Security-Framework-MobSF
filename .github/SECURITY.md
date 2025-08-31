# Security Policy

Keeping MobSF updated to the latest version is essential for ensuring security and stability.

## Reporting a Vulnerability

Please report all security issues [here](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/new) or email ajin25(gmail). We believe in coordinated and responsible disclosure.

## Past Security Issues

| Vulnerability | Affected Versions |
| ------- | ------------------ |
| [Arbitrary File Write (AR-Slip) via Absolute Path in .a Extraction](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-9gh8-9r95-3fc3) | `<=4.4.0` |
| [Path Traversal in GET /download/`<filename>` using absolute filenames in MobSF data directory)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-ccc3-fvfx-mw3v) | `<=4.4.0` |
| [Zip bomb Denial of Service (DoS) via Resource Exhaustion (Disk Space)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-c5vg-26p8-q8cr) | `<=4.3.2` |
| [Stored Cross Site Scripting (XSS) via malicious SVG app icon](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-mwfg-948f-2cc5) | `<=4.3.2` |
| [SSRF on assetlinks_check with DNS Rebinding](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-fcfq-m8p6-gw56) | `<=4.3.1` |
| [Partial Denial of Service due to strict regex check in iOS report view URL](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-jrm8-xgf3-fwqr) | `<=4.3.0` |
| [Local Privilege escalation due to leaked REST API key in web UI](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-79f6-p65j-3m2m) | `<=4.3.0` |
| [Stored Cross-Site Scripting in iOS dynamic_analysis view via `bundle` id](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-cxqq-w3x5-7ph3) | `<=4.3.0` |
| [Stored Cross-Site Scripting Vulnerability in Recent Scans "Diff or Compare"](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-5jc6-h9w7-jm3p) | `<=4.2.8` |
| [Zip Slip Vulnerability in .a extraction](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-4hh3-vj32-gr6j) | `<=4.0.6` |
| [Open Redirect in Login redirect](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-8m9j-2f32-2vx4) | `<=4.0.4` |
| [SSRF in firebase database check](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-wpff-wm84-x5cx) | `<=3.9.7` |
| [SSRF in AppLink check via abusing url redirect](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-m435-9v6r-v5f6) | `<=3.9.6` |
| [SSRF in AppLink check via crafted android:host](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-wfgj-wrgh-h3r3) | `<=3.9.5`|
| [Arbitrary Local file read in APK icon resource](https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/a58f8a8c0aa49e1581d97e19e8e2255ca96cd838)  | `>=1.0.4, <=3.9.2` |
| [Remote Code Execution via arbitrary file overwrite vulnerability in apktool <2.9.2](https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/19c1b55c2c59596f2d43439926c9dc976cbeaec4),  [[CVE-2024-21633]](https://github.com/0x33c0unt/CVE-2024-21633) | `<=3.9.1` |
| [Arbitrary Local file read regression](https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/1197)  | `<3.0.0` |
| [Upload a malicious zip file can overwrite arbitary files](https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/358)  | `>=0.9.3.2, <=0.9.4.1` |
| [Arbitrary Local file read](https://github.com/MobSF/Mobile-Security-Framework-MobSF/pull/166) | `<=0.9.2` |

