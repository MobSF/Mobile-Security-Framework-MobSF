YARA_URL="https://github.com/rednaga/yara-python-1"
git clone --recursive ${YARA_URL} yara-python
cd yara-python
python3 setup.py build --enable-dex install
cd ..
rmdir yara-python /S
