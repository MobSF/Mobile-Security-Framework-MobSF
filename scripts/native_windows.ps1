param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$DataRoot,
    [ValidateSet('install', 'start', 'doctor', 'android-check', 'proxy-check', 'password')]
    [string]$Action = 'start'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $Program (exit $LASTEXITCODE)" }
}

try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'This installer requires Windows x64.' }
    $SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
    New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
    $DataRoot = (Resolve-Path -LiteralPath $DataRoot).Path
    $config = Join-Path $DataRoot 'desktop.env'
    # Parse data as data: never dot-source configuration or evaluate expressions.
    $allowed = @('MOBSF_ADMIN_PASSWORD', 'MOBSF_ANDROID_MODERN_DYNAMIC',
        'MOBSF_ANDROID_ALLOW_LOW_TARGET_INSTALL', 'MOBSF_ANALYZER_IDENTIFIER',
        'MOBSF_CAPTURE_PROXY_PROVIDER', 'MOBSF_CAPTURE_PROXY_URL', 'MOBSF_CAPTURE_PROXY_CA_FILE')
    foreach ($line in [IO.File]::ReadAllLines($config)) {
        if ($line.Trim().Length -eq 0 -or $line.StartsWith('#')) { continue }
        # -split works on Windows PowerShell 5.1/.NET Framework too. String.Split
        # with a string array and integer selects the options overload there.
        $pair = $line -split '=', 2
        if ($pair.Count -ne 2 -or $pair[0] -notin $allowed) { throw 'Invalid desktop.env setting.' }
        [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'Process')
    }
    $env:MOBSF_HOME_DIR = Join-Path $DataRoot 'data'
    $env:XDG_CONFIG_HOME = Join-Path $DataRoot 'config'
    $env:XDG_CACHE_HOME = Join-Path $DataRoot 'cache'
    $env:MOBSF_DISABLE_AUTHENTICATION = '0'
    $env:MOBSF_ASYNC_ANALYSIS = '0'
    $env:MOBSF_ALLOWED_HOSTS = 'localhost,127.0.0.1'
    $env:POETRY_CACHE_DIR = Join-Path $DataRoot 'cache\poetry'
    $env:POETRY_CONFIG_DIR = Join-Path $DataRoot 'config\poetry'
    $env:POETRY_INSTALLER_MAX_WORKERS = '4'
    foreach ($dir in @($env:MOBSF_HOME_DIR, $env:XDG_CONFIG_HOME, $env:XDG_CACHE_HOME)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    # Prefer a full Python installation; Windows Store aliases are not runtimes.
    $python = $null
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $candidate = & $launcher.Source -3.12 -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and $candidate) { $python = [string]$candidate }
    }
    if (-not $python) {
        $candidate = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($candidate) { $python = $candidate.Source }
    }
    if (-not $python) { throw 'Install Python 3.12 x64: winget install --exact --id Python.Python.3.12; then reopen this console.' }
    Invoke-Checked $python @('-c', "import sys,struct; assert sys.version_info[:2] == (3,12) and struct.calcsize('P') == 8, 'Python 3.12 x64 is required'")
    $java = $null
    if ($env:JAVA_HOME) { $java = Join-Path $env:JAVA_HOME 'bin\java.exe' }
    if (-not $java -or -not (Test-Path -LiteralPath $java)) {
        $candidate = Get-Command java.exe -ErrorAction SilentlyContinue
        if ($candidate) { $java = $candidate.Source }
    }
    if (-not $java) { throw 'Install Java 21: winget install --exact --id EclipseAdoptium.Temurin.21.JDK; then reopen this console.' }
    # Java version writes to stderr; capture without PowerShell native-error promotion.
    $javaVersion = & $python -c "import subprocess,sys; p=subprocess.run([sys.argv[1],'-version'],capture_output=True,text=True,check=True); print(p.stderr+p.stdout)" $java
    if ($LASTEXITCODE -ne 0 -or "$javaVersion" -notmatch 'version "(\d+)') { throw 'Unable to determine Java version.' }
    if ([int]$Matches[1] -lt 21) { throw 'Java 21 or later is required.' }
    $env:MOBSF_JAVA_DIRECTORY = Split-Path -Parent $java
    Write-Host 'Python 3.12 x64 and Java 21+ are available. No Docker or WSL is required.'
    $venv = Join-Path $SourceRoot '.venv'
    $runtimePython = Join-Path $venv 'Scripts\python.exe'
    $env:PATH = (Join-Path $venv 'Scripts') + ';' + $env:PATH
    $ready = Join-Path $venv 'mobsf-installed.txt'
    Push-Location -LiteralPath $SourceRoot
    try {
        if ($Action -in @('install', 'start') -and -not (Test-Path -LiteralPath $ready)) {
            Write-Host 'Installing locked native dependencies. First installation requires Internet.'
            $tooling = Join-Path $DataRoot 'tooling\poetry-1.8.4'
            $toolPython = Join-Path $tooling 'Scripts\python.exe'
            if (-not (Test-Path -LiteralPath $toolPython)) { Invoke-Checked $python @('-m', 'venv', $tooling) }
            Invoke-Checked $toolPython @('-m', 'pip', 'install', '--disable-pip-version-check', 'poetry==1.8.4')
            if (-not (Test-Path -LiteralPath $runtimePython)) { Invoke-Checked $python @('-m', 'venv', $venv) }
            $env:VIRTUAL_ENV = $venv
            $env:POETRY_VIRTUALENVS_CREATE = 'false'
            Invoke-Checked $toolPython @('-m', 'poetry', 'install', '--only', 'main', '--no-root', '--no-interaction', '--no-ansi')
            Invoke-Checked $runtimePython @('-m', 'pip', 'check')
            Invoke-Checked $runtimePython @('scripts/native_runtime.py', 'initialize')
            [IO.File]::WriteAllText($ready, 'Locked native dependencies installed successfully.')
        }
        if (-not (Test-Path -LiteralPath $ready)) {
            if ($Action -eq 'doctor') { Write-Host 'Runtime is not installed yet. Run MobSF-BugBounty.exe install.'; exit 0 }
            throw 'Run MobSF-BugBounty.exe install first.'
        }
        switch ($Action) {
            'install' { Write-Host 'Native installation is ready. Run start, then credentials in another console.' }
            'start' { Invoke-Checked $runtimePython @('scripts/native_runtime.py', 'serve') }
            'doctor' { Invoke-Checked $runtimePython @('scripts/native_runtime.py', 'doctor') }
            'password' { Invoke-Checked $runtimePython @('manage.py', 'changepassword', 'mobsf') }
            'proxy-check' { Invoke-Checked $runtimePython @('manage.py', 'proxy_preflight') }
            'android-check' { Invoke-Checked $runtimePython @('manage.py', 'android_preflight', '--json') }
        }
    } finally { Pop-Location }
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
}
