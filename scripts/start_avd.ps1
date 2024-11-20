# Check if AVD_NAME and START_PORT are provided as arguments
param (
    [string]$AVD_NAME,
    [string]$START_PORT = "5554"
)

# Determine the emulator path based on Windows Android SDK location
$EMULATOR_PATH = "$env:LOCALAPPDATA\Android\Sdk\emulator\emulator.exe"
if (!(Test-Path $EMULATOR_PATH)) {
    Write-Output "Emulator not found at $EMULATOR_PATH"
    exit 1
}

# Locate adb path
$ADB_PATH = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
if (!(Test-Path $ADB_PATH)) {
    $ADB_PATH = (where adb | Select-Object -First 1).ToString().Trim()
}

# Check if adb is available
if (!(Test-Path $ADB_PATH)) {
    Write-Output "adb not found in common locations. Defaulting to 'adb' in PATH."
    $ADB_PATH = "adb"
}

# If no AVD_NAME is provided, list available AVDs and exit
if (-not $AVD_NAME) {
    Write-Output "Available AVDs:"
    & "$EMULATOR_PATH" -list-avds
    Write-Output "Use any Android AVD 5.0 - 11, up to API 30 without Google Play (production image)."
    Write-Output "Usage: .\script.ps1 -AVD_NAME <AVD_NAME> [-START_PORT <START_PORT>]"
    Write-Output "Example: .\script.ps1 -AVD_NAME Pixel_6_Pro_API_28 -START_PORT 5554"
    exit 1
}

# Check if provided AVD_NAME exists in available AVDs
$AVD_FOUND = $false
$AVAILABLE_AVDS = & "$EMULATOR_PATH" -list-avds
foreach ($avd in $AVAILABLE_AVDS) {
    if ($avd -eq $AVD_NAME) {
        $AVD_FOUND = $true
        break
    }
}

if (-not $AVD_FOUND) {
    Write-Output "Error: AVD $AVD_NAME not found in available AVDs."
    Write-Output "Available AVDs:"
    Write-Output $AVAILABLE_AVDS
    exit 1
}

# Start the emulator with user-defined AVD and port
Start-Process -FilePath $EMULATOR_PATH -ArgumentList "-avd $AVD_NAME -writable-system -no-snapshot -wipe-data -port $START_PORT"
Write-Output "Emulator started with AVD $AVD_NAME on port $START_PORT."