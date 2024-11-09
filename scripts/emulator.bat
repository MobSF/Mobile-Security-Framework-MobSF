@echo off
setlocal

:: Check if AVD_NAME, START_PORT, and GAPPS_ZIP are provided as arguments
set "AVD_NAME=%1"
set "START_PORT=%2"
if not defined START_PORT set "START_PORT=5554"
set "GAPPS_ZIP=%3"

:: Determine the emulator path based on Windows Android SDK location
set "EMULATOR_PATH=%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe"
if not exist "%EMULATOR_PATH%" (
    echo Emulator not found at %EMULATOR_PATH%
    exit /b 1
)

:: Locate adb path
set "ADB_PATH=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"
if not exist "%ADB_PATH%" (
    for /f "tokens=*" %%A in ('where adb') do set "ADB_PATH=%%A"
)

:: Check if adb is available
if not exist "%ADB_PATH%" (
    echo adb not found in common locations. Defaulting to 'adb' in PATH.
    set "ADB_PATH=adb"
)

:: If no AVD_NAME is provided, list available AVDs and exit
if "%AVD_NAME%"=="" (
    echo Available AVDs:
    "%EMULATOR_PATH%" -list-avds
    echo Use any Android AVD 5.0 - 9.0, up to API 28 without Google Play (production image).
    echo Usage: %~nx0 AVD_NAME [START_PORT] [open_gapps.zip path]
    echo Example: %~nx0 Pixel_6_Pro_API_28 5554 C:\path\to\open_gapps.zip
    exit /b 1
)

:: Check if provided AVD_NAME exists in available AVDs
for /f "tokens=*" %%A in ('"%EMULATOR_PATH%" -list-avds') do (
    if "%%A"=="%AVD_NAME%" set "AVD_FOUND=true"
)
if not defined AVD_FOUND (
    echo Error: AVD %AVD_NAME% not found in available AVDs.
    echo Available AVDs:
    "%EMULATOR_PATH%" -list-avds
    exit /b 1
)

:: Kill any existing emulator processes
for /f "tokens=5" %%a in ('tasklist ^| findstr emulator.exe') do (
    echo Killing emulator process with PID %%a
    taskkill /PID %%a /F
)

:: Start the emulator with user-defined AVD and port
start "" "%EMULATOR_PATH%" -avd "%AVD_NAME%" -writable-system -no-snapshot -wipe-data -port %START_PORT%
echo Emulator started with AVD %AVD_NAME% on port %START_PORT%.


:: Install Play Store if open_gapps.zip is provided
if not "%GAPPS_ZIP%"=="" (
    if not exist "%GAPPS_ZIP%" (
        echo Error: File %GAPPS_ZIP% not found.
        exit /b 1
    )

    echo Installing PlayStore

    :: Check for unzip and lzip tools
    where unzip >nul 2>&1
    if %errorlevel% neq 0 (
        echo Error: unzip is not installed.
        exit /b 1
    )

    where lzip >nul 2>&1
    if %errorlevel% neq 0 (
        echo Error: lzip is not installed.
        exit /b 1
    )

    set "PLAY_EXTRACT_DIR=play"
    if exist "%PLAY_EXTRACT_DIR%" rmdir /s /q "%PLAY_EXTRACT_DIR%"
    mkdir "%PLAY_EXTRACT_DIR%"
    
    unzip "%GAPPS_ZIP%" "Core/*" -d "%PLAY_EXTRACT_DIR%" || (echo Error: Unzip failed && exit /b 1)
    del /q "%PLAY_EXTRACT_DIR%\Core\setup*"
    
    for %%f in ("%PLAY_EXTRACT_DIR%\Core\*.lz") do (
        lzip -d "%%f" || (echo Error: Decompression failed && exit /b 1)
    )

    for %%f in ("%PLAY_EXTRACT_DIR%\Core\*.tar") do (
        tar -xf "%%f" --strip-components=2 -C "%PLAY_EXTRACT_DIR%" || (echo Error: Extraction failed && exit /b 1)
    )

    echo Waiting for emulator to complete booting...
    timeout /t 25 /nobreak >nul

    echo Installing PlayStore components
    "%ADB_PATH%" root
    "%ADB_PATH%" remount >nul 2>&1
    "%ADB_PATH%" push "%PLAY_EXTRACT_DIR%\etc" /system
    "%ADB_PATH%" push "%PLAY_EXTRACT_DIR%\framework" /system
    "%ADB_PATH%" push "%PLAY_EXTRACT_DIR%\app" /system
    "%ADB_PATH%" push "%PLAY_EXTRACT_DIR%\priv-app" /system
    "%ADB_PATH%" shell stop
    "%ADB_PATH%" shell start
    if exist "%PLAY_EXTRACT_DIR%" rmdir /s /q "%PLAY_EXTRACT_DIR%"
    echo PlayStore installed successfully
) else (
    echo No open_gapps.zip provided. Skipping Play Store installation.
)

endlocal
