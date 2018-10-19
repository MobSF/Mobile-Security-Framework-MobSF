where python3 >nul 2>&1 && (
  echo "[INSTALL] Found Python3"
  echo '[INSTALL] Installing Virtualenv'
  python3 -m pip install virtualenv
  virtualenv -p python3 ./venv
  .\venv\Scripts\activate
  echo '[INSTALL] Installing Requirements'
  pip install -r requirements.txt
   echo '[INSTALL] Installation Complete'
) || (
  echo "[ERROR] python3 is not installed"

)