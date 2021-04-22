@echo off
rem Python Check
where python >nul 2>&1 && (
  echo [INSTALL] Python is available
  :redo
  rem Python Version Check
  for /F "tokens=* USEBACKQ" %%F IN (`python --version`) DO (
    set var=%%F
  )
  echo %var%|findstr /R "[3].[89]" >nul
  if errorlevel 1 (
      if "%var%"=="" goto redo
      echo [ERROR] MobSF dependencies require Python 3.8/3.9. Your python points to %var%
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
   echo [INFO] Install OpenSSL non-light version - https://slproweb.com/products/Win32OpenSSL.html
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

  rem Create venv
  echo [INSTALL] Creating venv
  rmdir "venv" /q /s >nul 2>&1
  python -m venv ./venv
  set venv=.\venv\Scripts\python
  %venv% -m pip install --upgrade pip

  set LIB=C:\Program Files\OpenSSL-Win64\lib;%LIB%
  set INCLUDE=C:\Program Files\OpenSSL-Win64\include;%INCLUDE%

  echo [INSTALL] Installing Requirements
  %venv% -m pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt
  
  echo [INSTALL] Clean Up
  call scripts/clean.bat y

  echo [INSTALL] Migrating Database
  %venv% manage.py makemigrations
  %venv% manage.py makemigrations StaticAnalyzer
  %venv% manage.py migrate
  echo Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html
  echo [INSTALL] Installation Complete
  %venv% scripts/check_install.py
  exit /b 0
) || (
  echo [ERROR] python3 is not installed
)
