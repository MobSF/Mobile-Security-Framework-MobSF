param(
    [string]$Executable = (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\MobSF-BugBounty.exe'),
    [string]$PythonExecutable = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sourceRoot = Split-Path -Parent $PSScriptRoot
$savedEnvironment = @{}
$names = @('APPDATA', 'MOBSF_HOME_DIR', 'MOBSF_DISABLE_AUTHENTICATION',
    'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy',
    'MOBSF_UPSTREAM_PROXY_ENABLED', 'MOBSF_UPSTREAM_PROXY_IP', 'MOBSF_UPSTREAM_PROXY_PORT')
foreach ($name in $names) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Invoke-Verified([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Validation command failed: $Program (exit $LASTEXITCODE)" }
}

try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Use Windows 11 x64 for this notebook validation.' }
    $Executable = (Resolve-Path -LiteralPath $Executable).Path
    $lab = Join-Path $env:LOCALAPPDATA ('MobSF-Validation\' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $lab | Out-Null
    $env:APPDATA = Join-Path $lab 'profile'
    Write-Host "Isolated test profile: $lab"
    Write-Host 'Close an existing MobSF console before testing; port 8000 must be free.'
    Write-Host ('Executable SHA256: ' + (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash)
    $driver = Join-Path $lab 'driver'
    Invoke-Verified $PythonExecutable @('-m', 'venv', $driver)
    $driverPython = Join-Path $driver 'Scripts\python.exe'
    Invoke-Verified $driverPython @('-m', 'pip', 'install', '--disable-pip-version-check', 'requests==2.32.5')
    Push-Location -LiteralPath $sourceRoot
    try {
        Invoke-Verified $Executable @('self-test')
        Invoke-Verified $driverPython @('scripts/smoke_native_windows.py', '--executable', $Executable)
        $profile = Join-Path $env:APPDATA 'MobSF-BugBounty'
        $runtimePython = Get-ChildItem -LiteralPath (Join-Path $profile 'app') -Directory |
            ForEach-Object { Join-Path $_.FullName '.venv\Scripts\python.exe' } |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $runtimePython) { throw 'Native dependency interpreter was not installed.' }
        Invoke-Verified $runtimePython @('scripts/smoke_proxy_chain.py', '--runtime-python', $runtimePython)
        # Synthetic regressions cannot contact external targets. Test-only legacy
        # authentication flags are restored before this script returns.
        $env:MOBSF_HOME_DIR = Join-Path $profile 'data'
        $env:MOBSF_DISABLE_AUTHENTICATION = '1'
        foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')) {
            [Environment]::SetEnvironmentVariable($name, 'http://127.0.0.1:9', 'Process')
        }
        $env:NO_PROXY = 'localhost,127.0.0.1'
        $env:no_proxy = $env:NO_PROXY
        $env:MOBSF_UPSTREAM_PROXY_ENABLED = '1'
        $env:MOBSF_UPSTREAM_PROXY_IP = '127.0.0.1'
        $env:MOBSF_UPSTREAM_PROXY_PORT = '9'
        Invoke-Verified $runtimePython @('manage.py', 'test', 'mobsf.BugBounty', 'mobsf.DynamicAnalyzer', '--noinput')
        Write-Host "Native installation, scan, restart, proxy TLS and synthetic regressions passed. Logs remain in $lab"
    } finally { Pop-Location }
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
} finally {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
