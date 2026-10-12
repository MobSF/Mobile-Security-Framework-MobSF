# Native Windows executable — standalone edition

`windows/MobSF-BugBounty.exe` installs this bundled edition natively on Windows
x64 and serves it with Waitress. Docker, WSL, Git and Go are unnecessary for
end users. The application source and Windows iOS icon converter are embedded;
Python packages and JADX are installed on first use over verified HTTPS.

## Install and use

Use Windows 11 x64 with a full Python 3.12 x64 installation and Java 21+.
Install the prerequisites from their official distributions or with WinGet:

```powershell
winget install --exact --id Python.Python.3.12
winget install --exact --id EclipseAdoptium.Temurin.21.JDK
```

Reopen the console after installation. Download the executable and SHA256SUMS
from `standalone/bug-bounty-edition` or a successful Windows workflow artifact.
Verify the hash, then install and start:

```powershell
Get-FileHash ./MobSF-BugBounty.exe -Algorithm SHA256
./MobSF-BugBounty.exe self-test
./MobSF-BugBounty.exe install
./MobSF-BugBounty.exe doctor
./MobSF-BugBounty.exe start
```

Double-clicking also installs missing application dependencies and starts MobSF.
The console stays open while the native server runs. Press Ctrl+C in that
console to stop. Application logs appear there; capture diagnostics are written
to `%APPDATA%\MobSF-BugBounty\data\capture-proxy.log`.
In a second console, retrieve the initial random password or change it:

```powershell
./MobSF-BugBounty.exe credentials
./MobSF-BugBounty.exe password
./MobSF-BugBounty.exe android-check
./MobSF-BugBounty.exe proxy-check
```

Login uses `mobsf` and a random password unique to the installation. Authentication
is required. Initial credentials are printed only on explicit request and can
become stale after a password change. Existing accounts are preserved. Use the
[proxy integration guide](PROXY_INTEGRATION.md) for Burp Suite Professional/Caido.

## Runtime and data

Everything managed by the launcher lives under `%APPDATA%\MobSF-BugBounty`:

| Path | Purpose |
| --- | --- |
| `app/<source SHA256>/` | Extracted application and its isolated `.venv` |
| `data/` | SQLite, uploads, findings, signatures, JADX, capture flows and local CA |
| `desktop.env` | Initial password, Android settings and interception proxy settings |
| `tooling/`, `cache/`, `config/` | Isolated Poetry 1.8.4 and package/tool caches |

First installation needs Internet and several GB of free disk space. It installs
`poetry.lock` without regenerating it, checks dependencies and applies checked-in
migrations. It does not run the old setup.bat cleanup, create a default password,
install the obsolete Windows RPC/APPX service or register startup tasks. The
system Python installation and PATH are unchanged; runtime PATH changes exist
only in the launcher process. Async analysis is off in this desktop edition.

Back up the entire profile directory before upgrading. New executables extract
a different source hash and retain `data/`; migrations also run at server start.
Old Docker named volumes are separate and are not silently imported or deleted.
Windows data privacy relies on inherited user profile ACLs; Unix permissions
alone do not configure NTFS access controls. Keep the directory private and out
of cloud sync/source control.

Waitress reserves only loopback port 8000. A conflicting service causes an error
and is never killed. Browser startup requires both the owned runtime's health
nonce and a real login page with CSRF. Proxy port 1337 also defaults to loopback;
Android emulator/USB capture can use ADB reverse. A native Android SDK/ADB and an
authorized rooted lab are separate prerequisites for dynamic analysis.

## Optional functionality

PDF export requires a separately installed wkhtmltopdf binary on PATH;
`doctor` reports when it is absent. APK/IPA JSON reports and workspace exports
remain available without it. Modern Android TLS interception requires an
explicit lab trust configuration; the launcher does not install a system CA
on Android 12–17. Native APPX analysis requiring Microsoft's legacy RPC stack
is outside this installer. Python 3.13+, ARM Windows, signed distribution,
SmartScreen behavior and restore drills remain unvalidated.

## Build and validation

Developers need Python 3.12, Git and Go 1.24+. Stage new source files, then run:

```powershell
./scripts/build_windows.ps1
```

Packaging is deterministic and includes upstream GPL/third-party licenses;
Linux PNG converters, source maps and submodule test fixtures are omitted from
the native bundle. The Go BSD license is distributed alongside the executable.
The executable is unsigned. The cloud environment cross-compiles the real PE
and validates the same native server on Linux; this is distinct from Windows
execution. The Windows workflow builds and executes the EXE, then tests native
installation, dependency imports, login, Android 17 scan, workspace import and
restart persistence. See TEST_RESULTS.md for actually executed results; a
configured workflow alone does not establish a passed Windows run.
