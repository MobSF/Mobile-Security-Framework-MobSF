# Windows executable — standalone edition

`windows/MobSF-BugBounty.exe` is an x64 console launcher with this edition's
application source embedded in it. It runs MobSF in Docker Desktop Linux
containers and opens the local workspace after readiness checks. It is not a
native standalone replacement for Docker, Python's application server or an
Android emulator. Host Python, Java and Git are unnecessary for end users.
The runtime bundle omits JavaScript debug maps, test fixture submodules and the
legacy native Windows PNG converter, which are unnecessary inside Linux Docker.
The upstream license and third-party LICENSES directory are included.
The Go runtime's BSD license is provided alongside the executable as
windows/GO-LICENSE.txt and included in the workflow distribution.
Packaging preserves executable modes from Git rather than Windows filesystem
metadata; the Dockerfile also sets the script and Linux converter permissions.

## Install and use

1. Install Docker Desktop with the WSL2 backend on a supported Windows 11 x64
   machine; enable virtualization and start Docker Desktop in Linux mode.
2. Download the executable and `windows/SHA256SUMS` from the
   `standalone/bug-bounty-edition` branch of this fork, or the successful
   `Standalone Windows launcher` workflow artifact.
3. Verify the executable's SHA256 against that file, then double-click it.
   First startup builds the embedded edition and needs Internet, disk space and
   several minutes. Later starts reuse its exact source-version image.
4. Retrieve the randomly generated initial login password explicitly using
   the `credentials` command, then choose your own password using `password`.

From PowerShell in the download folder:

```powershell
Get-FileHash ./MobSF-BugBounty.exe -Algorithm SHA256
./MobSF-BugBounty.exe doctor
./MobSF-BugBounty.exe self-test
./MobSF-BugBounty.exe
./MobSF-BugBounty.exe credentials
./MobSF-BugBounty.exe password
./MobSF-BugBounty.exe status
./MobSF-BugBounty.exe android-check
./MobSF-BugBounty.exe logs
./MobSF-BugBounty.exe stop
```

The executable is unsigned. Publisher identity/signing and SmartScreen behavior
have not been validated. Verify origin and checksum according to your Windows
policy; this guide does not recommend disabling Windows protections.

## Storage, connectivity and updates

Source versions and `desktop.env` live under `%APPDATA%\MobSF-BugBounty` on
Windows. The initial random password is saved there and only printed when you
explicitly request `credentials`; it can become stale after a password change.
Keep that user profile directory private and out of cloud sync or source control.
Windows file access relies on inherited user profile ACLs; Unix mode 0600 alone
does not configure a Windows ACL.

The Compose project is consistently named `mobsf-bounty-desktop`. SQLite and
analysis artifacts persist in its `mobsf_data` named volume. Stop preserves
data. Do not delete the volume or run `down -v` to update. Back up the full data
volume before running a newer executable; the new embedded source is extracted
to a different hash directory and migrations run against retained data. Restore
and migration rollback procedures still need an independent drill.

Application and proxy ports 8000 and 1337 bind to loopback. A port conflict is an
error; the launcher does not stop unrelated services. Docker readiness, the
owned service's health and the login response are checked before opening the
browser. Docker Desktop availability and a reachable, authorized Android device
are separate prerequisites. See ANDROID_COMPATIBILITY.md for modern-device
requirements and network/TLS limitations.

Configuration changes in `desktop.env` take effect on the next start. They do
not rotate an existing user's password; use `password`. The build does not
download a moving upstream source branch: it compiles the embedded checkout.
The base image and signed distribution package updates still follow the
Dockerfile policy; pin reviewed image digests for production deployment.

## Rebuild from source

Developers need Python 3.12+ for source packaging, Git and Go 1.24+ for the
dependency-free launcher. Stage newly added source files so packaging includes
them, then run from PowerShell:

```powershell
./scripts/build_windows.ps1
```

The script runs Go tests and vet, cross-compiles Windows x64, writes checksums
and runs the resulting executable's extraction/configuration self-test when
on Windows. The branch-specific GitHub workflow performs the Windows build and
uploads the executable and checksum; it does not publish a release or alter
master. A successful workflow does not validate a full Docker Desktop session.

The cloud build cross-compiles the actual PE executable and runs equivalent
launcher tests on Linux. Full interactive Windows/Docker Desktop operation
remains untested until independently executed on that platform. See
TEST_RESULTS.md for measured validation rather than inferred compatibility.
