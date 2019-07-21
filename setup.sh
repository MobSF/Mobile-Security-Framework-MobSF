#!/bin/bash
if ! [ -x "$(command -v python3)" ]; then
  echo '[ERROR] python3 is not installed.' >&2
  exit 1
fi
echo '[INSTALL] Found Python3'

command
status=$?
cmd='python3 -m pip -V'
$cmd
status=$?
if [ $status -eq 0 ]; then
  echo '[INSTALL] Found pip'
  python3 -m pip install --upgrade pip
else
  echo "[ERROR] The command ($cmd) failed. python3-pip not installed"
  exit 1
fi

echo '[INSTALL] Installing virtualenv'
python3 -m pip install virtualenv
python3 -m virtualenv venv -p python3
source venv/bin/activate

unamestr=$(uname)
if [[ "$unamestr" == 'Darwin' ]]; then
  export ARCHFLAGS='-arch x86_64'
  export LDFLAGS='-L/usr/local/opt/openssl/lib'
  export CFLAGS='-I/usr/local/opt/openssl/include'  
fi

echo '[INSTALL] Installing APKiD requirements - yara-python'
pip install wheel
pip wheel --wheel-dir=/tmp/yara-python --build-option='build' --build-option='--enable-dex' git+https://github.com/VirusTotal/yara-python.git@v3.10.0
pip install --no-index --find-links=/tmp/yara-python yara-python

echo '[INSTALL] Installing Requirements'
pip install -r requirements.txt

echo '[INSTALL] Clean Up'
bash scripts/clean.sh y

echo '[INSTALL] Migrating Database'
python manage.py makemigrations
python manage.py makemigrations StaticAnalyzer
python manage.py migrate
echo 'Download and Install wkhtmltopdf for PDF Report Generation - https://wkhtmltopdf.org/downloads.html'
echo '[INSTALL] Installation Complete'
