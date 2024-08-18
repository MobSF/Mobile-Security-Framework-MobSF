# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :x:                |
| 2.0.x   | :x:                |
| 3.0.x   | :white_check_mark: |
| 4.0.x   | :white_check_mark: |


## Reporting a Vulnerability

Please report all security issues [here](https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues) or email ajin25(gmail). We believe in coordinated and responsible disclosure.

## Past Security Issues

| Vulnerability | Affected Versions |
| ------- | ------------------ |
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

