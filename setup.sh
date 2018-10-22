if ! [ -x "$(command -v python3)" ]; then
  echo '[ERROR] python3 is not installed.' >&2
  exit 1
fi
echo '[INSTALL] Found Python3'
echo '[INSTALL] Installing Virtualenv'
python3 -m pip install virtualenv
echo '[INSTALL] Using Virtualenv'
virtualenv venv -p python3
source venv/bin/activate
platform='unknown'
unamestr=`uname`
if [[ "$unamestr" == 'Darwin' ]]; then
  export ARCHFLAGS="-arch x86_64"
  export LDFLAGS="-L/usr/local/opt/openssl/lib"
  export CFLAGS="-I/usr/local/opt/openssl/include"  
fi
echo '[INSTALL] Installing Requirements'
pip install -r requirements.txt
echo '[INSTALL] Installation Complete'
