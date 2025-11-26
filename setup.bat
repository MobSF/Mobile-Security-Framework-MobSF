@echo off

rem ================================
rem   Python Detection (Windows)
rem ================================
echo [INSTALL] Checking for Python 3.12 or newer...

where py >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python launcher 'py' not found. Install Python 3.12+ from python.org.
  pause
  exit /b 1
)

for /f "tokens=* usebackq" %%F in (`py -3 --version`) do (
    set PYVERSION=%%F
)
echo %PYVERSION% | findstr /R "3\.12 3\.13" >nul
if errorlevel 1 (
    echo [ERROR] MobSF requires Python 3.12 or 3.13. Found: %PYVERSION%
    pause
    exit /b 1
)
echo [INSTALL] Found %PYVERSION%

rem ================================
rem  Pip Check
rem ================================
py -m pip --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] pip is missing. Reinstall Python with pip enabled.
  pause
  exit /b 1
)
echo [INSTALL] Found pip
py -m pip install --upgrade pip

rem ================================
rem   OpenSSL Check
rem ================================
if exist "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" (
  echo [INSTALL] Found OpenSSL
) else (
  echo [ERROR] OpenSSL not found in: C:\Program Files\OpenSSL-Win64
  pause
  exit /b 1
)

rem ================================
rem   Visual Studio Build Tools
rem ================================
if exist "D:\Vscode" (
  echo [INSTALL] Found Visual Studio Build Tools
) else (
  echo [ERROR] Visual Studio Build Tools NOT found.
  pause
  exit /b 1
)

rem ================================
rem   Install Poetry + Dependencies
rem ================================
echo [INSTALL] Installing Poetry and MobSF dependencies...
py -m pip install --no-cache-dir wheel poetry==1.8.4
py -m poetry lock
py -m poetry install --only main --no-root --no-interaction --no-ansi

rem ================================
rem   Database Migrations
rem ================================
echo [INSTALL] Running Database Migrations
set DJANGO_SUPERUSER_USERNAME=mobsf
set DJANGO_SUPERUSER_PASSWORD=mobsf

py -m poetry run python manage.py makemigrations
py -m poetry run python manage.py makemigrations StaticAnalyzer
py -m poetry run python manage.py migrate
py -m poetry run python manage.py createsuperuser --noinput --email ""
py -m poetry run python manage.py create_roles

echo [INSTALL] Setup Complete.
exit /b 0
