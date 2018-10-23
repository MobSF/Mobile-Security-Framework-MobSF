@echo off
where python >nul 2>&1 && (
  echo [INSTALL] Found Python3
  pip3 >nul 2>&1 && (
    echo [INSTALL] Found pip3
  ) || (
    echo [ERROR] pip3 is not available in PATH
    pause
    exit /b
  )
  if exist "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" (
    echo [INSTALL] Found OpenSSL executable
  ) else (
   echo [ERROR] OpenSSL executable not found in [C:\Program Files\OpenSSL-Win64\bin\openssl.exe]
   echo [ERROR] Install OpenSSL - https://slproweb.com/download/Win64OpenSSL-1_1_1.exe
   pause
   exit /b
  )
  echo [INSTALL] Installing Virtualenv
  pip3 install -U pip virtualenv
  virtualenv -p python ./venv
  .\venv\Scripts\activate
  set LIB=C:\Program Files\OpenSSL-Win64\lib;%LIB%
  set INCLUDE=C:\Program Files\OpenSSL-Win64\include;%INCLUDE%
  echo [INSTALL] Installing Requirements
  pip install -r requirements.txt
  echo [INSTALL] Installation Complete
) || (
  echo [ERROR] python3 is not installed
)
