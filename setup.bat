@echo off
rem Python Check
set /a count=0
where python >nul 2>&1 && (
  echo [INSTALL] Checking for Python version 3.9+
  :redo
  if %count% lss 3 (
    set /a count+=1
    rem Python Version Check
    for /F "tokens=* USEBACKQ" %%F IN (`python --version`) DO (
      set var=%%F
    )
  ) else (
    exit /b
  )
  echo %var%|findstr /R "[3].[91011]" >nul
  if errorlevel 1 (
      if "%var%"=="" goto redo
      echo [ERROR] MobSF dependencies require Python 3.9-3.11. Your python points to %var%
      exit /b
  ) else (
      echo [INSTALL] Found %var%
  )

  rem Pip Check and Upgrade
  pip >nul 2>&1 && (
    echo [INSTALL] Found pip
    python -m pip install --no-cache-dir --upgrade pip
  ) || (
    echo [ERROR] pip is not available in PATH
    pause
    exit /b
  )

  rem OpenSSL Check
  if exist "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe" (
    echo [INSTALL] Found OpenSSL executable
  ) else (
   echo [ERROR] OpenSSL executable not found in [C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe]
   echo [INFO] Install OpenSSL non-light version [Win64 OpenSSL v3.x] - https://slproweb.com/products/Win32OpenSSL.html
   pause
   exit /b
  )

  rem Visual Studio Build Tools Check
  if exist "C:\\Program Files (x86)\\Microsoft Visual Studio" (
    echo [INSTALL] Found Visual Studio Build Tools
  ) else (
    echo [ERROR] Microsoft Visual C++ 14.0 not found in [C:\\Program Files (x86^)\\Microsoft Visual Studio]
    echo [INFO] Install Microsoft Visual Studio Build Tools - https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools^&rel=16
    pause
    exit /b
  )

  set LIB=C:\Program Files\OpenSSL-Win64\lib;%LIB%
  set INCLUDE=C:\Program Files\OpenSSL-Win64\include;%INCLUDE%

  echo [INSTALL] Installing Requirements
  python -m pip install --no-cache-dir wheel poetry==1.6.1
  python -m poetry lock
  python -m poetry install --only main --no-root --no-interaction --no-ansi || python -m poetry install --only main --no-root --no-interaction --no-ansi || python -m poetry install --only main --no-root --no-interaction --no-ansi
 
  echo [INSTALL] Clean Up
  call scripts/clean.bat y

  echo [INSTALL] Migrating Database
  poetry run python manage.py makemigrations
  poetry run python manage.py makemigrations StaticAnalyzer
  poetry run python manage.py migrate
  echo Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html
  echo [INSTALL] Installation Complete
  exit /b 0
) || (
  echo [ERROR] python3 is not installed
)
