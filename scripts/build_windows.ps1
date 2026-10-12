param([string]$GoExecutable = "go")
$ErrorActionPreference = "Stop"
$sourceRoot = Split-Path -Parent $PSScriptRoot
Push-Location $sourceRoot
try {
    python scripts/package_desktop.py
    if ($LASTEXITCODE -ne 0) { throw "Source packaging failed" }
    New-Item -ItemType Directory -Force windows | Out-Null
    Push-Location desktop
    try {
        & $GoExecutable test ./...
        if ($LASTEXITCODE -ne 0) { throw "Launcher tests failed" }
        & $GoExecutable vet ./...
        if ($LASTEXITCODE -ne 0) { throw "Launcher vet failed" }
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        & $GoExecutable build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o ../windows/MobSF-BugBounty.exe .
        if ($LASTEXITCODE -ne 0) { throw "Windows compilation failed" }
    } finally { Pop-Location }
    $digest = (Get-FileHash windows/MobSF-BugBounty.exe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$digest  MobSF-BugBounty.exe" | Set-Content -Encoding ascii windows/SHA256SUMS
    if ([System.Environment]::OSVersion.Platform -eq "Win32NT") {
        & ./windows/MobSF-BugBounty.exe self-test
        if ($LASTEXITCODE -ne 0) { throw "Windows executable self-test failed" }
    }
} finally { Pop-Location }
