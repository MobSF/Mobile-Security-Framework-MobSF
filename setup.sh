#!/bin/bash

# Check for Python3 and validate version
if ! command -v python3 &>/dev/null; then
    echo '[ERROR] python3 is not installed.' >&2
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
py_major=${python_version%%.*}
py_minor=${python_version#*.}
py_minor=${py_minor%%.*}

if [[ "$py_major" -ne 3 || "$py_minor" -lt 10 || "$py_minor" -gt 12 ]]; then
    echo "[ERROR] MobSF dependencies require Python 3.10 - 3.12. You have Python ${python_version}."
    exit 1
fi
echo "[INSTALL] Found Python ${python_version}"

# Pip Check and Upgrade
python3 -m pip -V
if [ $? -eq 0 ]; then
    echo '[INSTALL] Found pip'
    # check if python is running in venv. The location for venv should be differ from /usr/lib/python3.xx
    pip_location=`python3 -m pip -V`
    if [[ $unamestr == 'Darwin' || "$pip_location" != "/usr/lib/python"* ]]; then
        python3 -m pip install --no-cache-dir --upgrade pip
    else
        python3 -m pip install --no-cache-dir --upgrade pip --user
    fi
else
    echo '[ERROR] python3-pip not installed'
    exit 1
fi

# macOS-specific Xcode CLI tools check
if [[ "$(uname)" == "Darwin" ]]; then
    if ! xcode-select -v &>/dev/null; then
        echo 'Please install command-line tools with: xcode-select --install'
        exit 1
    fi
    echo '[INSTALL] Found Xcode'
fi

# Install dependencies and set up the environment
echo '[INSTALL] Installing Requirements'
python3 -m pip install --no-cache-dir wheel poetry==1.8.4
python3 -m poetry lock
python3 -m poetry install --no-root --only main --no-interaction --no-ansi

echo '[INSTALL] Clean Up'
bash scripts/clean.sh y

# Database setup and superuser creation
echo '[INSTALL] Migrating Database'
export DJANGO_SUPERUSER_USERNAME=mobsf
export DJANGO_SUPERUSER_PASSWORD=mobsf
python3 -m poetry run python manage.py makemigrations
python3 -m poetry run python manage.py makemigrations StaticAnalyzer
python3 -m poetry run python manage.py migrate
python3 -m poetry run python manage.py createsuperuser --noinput --email ""
python3 -m poetry run python manage.py create_roles

# Check for wkhtmltopdf
if ! command -v wkhtmltopdf &>/dev/null; then
    echo 'Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html'
fi

echo '[INSTALL] Installation Complete'
