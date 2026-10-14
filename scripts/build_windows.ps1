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
    $goVersion = & $GoExecutable version
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read compiler version' }
    $sourceCommit = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read source commit' }
    $manifest = [ordered]@{
        source_commit = "$sourceCommit"
        source_tree_dirty = [bool](git status --porcelain --untracked-files=no -- . ':!windows')
        embedded_source_sha256 = (Get-FileHash desktop/resources/source.zip -Algorithm SHA256).Hash.ToLowerInvariant()
        executable_sha256 = $digest
        executable_bytes = (Get-Item windows/MobSF-BugBounty.exe).Length
        target = 'windows/amd64'
        compiler = "$goVersion".Split(' ')[2]
        build_platform = "$goVersion".Split(' ')[3]
        docker_desktop_required = $false
        runtime = 'native Python 3.12 x64 / Java 21+ / Waitress'
        windows_runtime_tested = $false
        code_signing = 'unsigned'
        licenses_included = $true
    }
    $manifest | ConvertTo-Json | Set-Content -Encoding ascii windows/build-manifest.json
    if ([System.Environment]::OSVersion.Platform -eq "Win32NT") {
        & ./windows/MobSF-BugBounty.exe self-test
        if ($LASTEXITCODE -ne 0) { throw "Windows executable self-test failed" }
    }
} finally { Pop-Location }
