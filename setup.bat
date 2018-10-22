@echo off
where python >nul 2>&1 && (
  echo [INSTALL] Found Python3
  echo [INSTALL] Installing Virtualenv
  pip3 install -U pip virtualenv
  virtualenv -p python ./venv
  .\venv\Scripts\activate
  echo [INSTALL] Installing Requirements
  pip install -r requirements.txt
  echo [INSTALL] Installation Complete
) || (
  echo [ERROR] python3 is not installed

)