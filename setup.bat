@echo off
where python >nul 2>&1 && (
  echo [INSTALL] Found Python3

  pip3 >nul 2>&1 && (
    echo [INSTALL] Found pip3
    python -m pip install --upgrade pip
  ) || (
    echo [ERROR] pip3 is not available in PATH
    pause
    exit /b
  )

  if exist "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe" (
    echo [INSTALL] Found OpenSSL executable
  ) else (
   echo [ERROR] OpenSSL executable not found in [C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe]
   echo [INFO] Download OpenSSL - https://indy.fulgan.com/SSL/openssl-1.0.2r-x64_86-win64.zip
   echo [INFO] Extract zip to C:\\Program Files\\OpenSSL-Win64\\bin\\ directory
   pause
   exit /b
  )

  if exist "C:\\Program Files (x86)\\Microsoft Visual Studio" (
    echo [INSTALL] Found Visual Studio Build Tools
  ) else (
    echo [ERROR] Microsoft Visual C++ 14.0 not found in [C:\\Program Files (x86^)\\Microsoft Visual Studio]
    echo [INFO] Install Microsoft Visual Studio Build Tools - https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools^&rel=16
    pause
    exit /b
  )

  echo [INSTALL] Using venv
  rmdir /q /s venv
  python -m venv ./venv
  .\venv\Scripts\activate

  set LIB=C:\Program Files\OpenSSL-Win64\lib;%LIB%
  set INCLUDE=C:\Program Files\OpenSSL-Win64\include;%INCLUDE%

  echo [INSTALL] Installing Requirements
  pip install -r requirements.txt

  echo [INSTALL] Migrating Database
  python manage.py makemigrations
  python manage.py makemigrations StaticAnalyzer
  python manage.py migrate
  echo Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html
  echo [INSTALL] Installation Complete
) || (
  echo [ERROR] python3 is not installed
)
