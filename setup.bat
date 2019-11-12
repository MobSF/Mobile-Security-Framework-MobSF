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
   echo [INFO] Install OpenSSL - https://slproweb.com/download/Win64OpenSSL-1_1_1d.exe
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

  echo [INSTALL] Installing dex enabled yara-python
  pip install --upgrade wheel
  rmdir /q /s yara-python
  pip wheel --wheel-dir=yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.10.0
  pip install --no-index --find-links=yara-python yara-python
  rmdir /q /s yara-python

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
