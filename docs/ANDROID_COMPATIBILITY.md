# Android compatibility in the standalone edition

This work exists only on `standalone/bug-bounty-edition`. Static APK analysis
does not require an Android device. The existing manifest version map includes
Android 12/12L, 13, 14, 15 and 16 (API 31 through 36). A target SDK value is not
proof that every feature or binary format from that release has been tested.

## Dynamic runtime changes

The original dynamic analyzer rejected every SDK above API 30. The standalone
edition retains its legacy path and adds an explicitly enabled experimental
modern path based on root, ABI and writable storage capabilities. Android 12–16
and higher numeric APIs no longer face an arbitrary API 30 ceiling in that mode.
Unknown releases remain labeled unmapped and unvalidated; no future version is
advertised as a tested release.

Modern Frida binaries and readiness markers use `/data/local/tmp/mobsf` instead
of `/system`. Modern setup does not remount /system. Download or upload failures
do not mark the runtime configured. Server version is matched to the locked
Python Frida client (17.18.0 at this revision); no blind client/server upgrade is
performed. ABI selection covers arm, arm64, x86 and x86_64.

The release property parser handles known preview codenames and Android 12L
without crashing existing version-dependent consumers. Unknown preview
codenames fail with a diagnostic until their mapping has been reviewed.

## Concrete lab setup

Use your own authorized AOSP/userdebug Android Studio AVD. Google Play production
images and ordinary unrooted phones cannot provide the required root ADB access.
Install current Android SDK Platform-Tools from Android Studio's SDK Manager.
Do not expose ADB to the public Internet or unrelated networks.

For native Linux with an already-running AVD:

```bash
adb devices
adb -s emulator-5554 root
adb -s emulator-5554 wait-for-device
export MOBSF_ANDROID_MODERN_DYNAMIC=1
export MOBSF_ANALYZER_IDENTIFIER=emulator-5554
source /workspace/.mobsf-setup/env.sh
.venv/bin/python manage.py android_preflight --identifier emulator-5554 --json
# Restart MobSF under those same environment variables, then use Dynamic Analysis.
```

Preflight only reads SDK/ABI/UID and tests directory access. It does not connect,
root, remount, install certificates, download Frida or change a device. A
non-ready result produces diagnostics and a nonzero exit status. Success means
prerequisites pass, not that application instrumentation has been verified.

For Docker Desktop, set `MOBSF_ANDROID_MODERN_DYNAMIC=1` and your authorized
device's reachable ADB endpoint in the launcher's `desktop.env`. The emulator
must be reachable from inside the Linux container; a Windows-host serial such
as `emulator-5554` alone is not a container connection. Use an isolated test
network, restrict the host firewall to that lab and verify the connection from
inside the container before starting analysis. Do not bind or expose host ADB
globally as a shortcut. Native ADB setup does not automatically make a device
reachable in Docker Desktop.
After configuring the endpoint and restarting the desktop service, run
`MobSF-BugBounty.exe android-check` for read-only diagnostics inside the container.

## Installation and TLS boundaries

Android 14+ may refuse apps targeting old SDK levels. An authorized isolated lab
can opt in with `MOBSF_ANDROID_ALLOW_LOW_TARGET_INSTALL=1`; the installer then
passes `--bypass-low-target-sdk-block` only on API 34+. The default remains off.
This does not fix minimum-SDK, CPU ABI, split-APK or signing incompatibilities.

Automatic modern system certificate modification is unavailable. Android 14+
uses the Conscrypt APEX trust store, and writing the old /system CA directory
would not establish reliable app trust. Certificate API operations report
failure instead of claiming success. Automated TLS verdict tests fail before
device actions on modern APIs because their controlled trust precondition
cannot be established. Use explicit authorized lab/application trust settings;
absence of captured HTTPS traffic proves no vulnerability or protection.

## Validation and update process

Synthetic tests exercise API 31–37 policy decisions, root/ABI/storage checks,
preview parsing, fail-closed setup, legacy failures and explicit installation
flags. No real Android 12–17 emulator or physical device has been run in this
cloud task. Device/build-specific Frida behavior, SELinux and CA trust still
require lab validation. Direct developer.android.com access was denied by the
cloud proxy, so no newly released Android version was independently verified.

Before extending the release map, check the official
[SDK platform release notes](https://developer.android.com/tools/releases/platforms)
and [behavior changes](https://developer.android.com/about/versions), review
Frida release notes, retain exact locked dependencies, and test the actual lab
image. Record its SDK, build fingerprint, ABI, client/server versions and
observed instrumentation/TLS results before marking it validated.
