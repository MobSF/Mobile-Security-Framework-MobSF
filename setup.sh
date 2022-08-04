#!/bin/bash

# Python3 Check
unamestr=$(uname)
if ! [ -x "$(command -v python3)" ]; then
    echo '[ERROR] python3 is not installed.' >&2
    exit 1
fi

# Python3 Version Check
python_version="$(python3 --version 2>&1 | awk '{print $2}')"
py_major=$(echo "$python_version" | cut -d'.' -f1)
py_minor=$(echo "$python_version" | cut -d'.' -f2)
if [ "$py_major" -eq "3" ] && [ "$py_minor" -gt "7" ]; then
    echo "[INSTALL] Found Python ${python_version}"
else
    echo "[ERROR] MobSF dependencies require Python 3.8/3.9. You have Python version ${python_version} or python3 points to Python ${python_version}."
    exit 1
fi

# Pip Check and Upgrade
python3 -m pip -V
if [ $? -eq 0 ]; then
    echo '[INSTALL] Found pip'
    if [[ $unamestr == 'Darwin' ]]; then
        python3 -m pip install --no-cache-dir --upgrade pip
    else
        python3 -m pip install --no-cache-dir --upgrade pip --user
    fi
else
    echo '[ERROR] python3-pip not installed'
    exit 1
fi

# macOS Specific Checks
if [[ $unamestr == 'Darwin' ]]; then
    # Check if xcode is installed
    xcode-select -v
    if ! [ $? -eq 0 ]; then
        echo 'Please install command-line tools'
        echo 'xcode-select --install'
        exit 1
    else
        echo '[INSTALL] Found Xcode'
	  fi    
fi

# Install venv
echo '[INSTALL] Using python virtualenv'
rm -rf ./venv
python3 -m venv ./venv
if [ $? -eq 0 ]; then
    echo '[INSTALL] Activating virtualenv'
    source venv/bin/activate
    pip install --upgrade pip
else
    echo '[ERROR] Failed to create virtualenv. Please install MobSF requirements mentioned in Documentation.'
    exit 1
fi

echo '[INSTALL] Installing Requirements'
pip install --no-cache-dir wheel
pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt

echo '[INSTALL] Clean Up'
bash scripts/clean.sh y

echo '[INSTALL] Migrating Database'
python manage.py makemigrations
python manage.py makemigrations StaticAnalyzer
python manage.py migrate
wkhtmltopdf -V
if ! [ $? -eq 0 ]; then
    echo 'Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html'
fi
echo '[INSTALL] Installation Complete'
python scripts/check_install.py
